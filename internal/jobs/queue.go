package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/config"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/core"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

const (
	queuePending    = "shells:queue:pending"
	queueProcessing = "shells:queue:processing"
	queueFailed     = "shells:queue:failed"
	jobPrefix       = "shells:job:"
	workerPrefix    = "shells:worker:"
)

type redisQueue struct {
	client *redis.Client
	cfg    config.RedisConfig
}

func NewRedisQueue(cfg config.RedisConfig) (core.JobQueue, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &redisQueue{
		client: client,
		cfg:    cfg,
	}, nil
}

func (q *redisQueue) Push(ctx context.Context, job *types.Job) error {
	if job.ID == "" {
		job.ID = uuid.New().String()
	}

	job.Status = "pending"
	job.CreatedAt = time.Now()
	job.UpdatedAt = job.CreatedAt

	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	pipe := q.client.Pipeline()

	pipe.Set(ctx, jobPrefix+job.ID, data, 24*time.Hour)

	score := float64(job.Priority)
	if job.Priority == 0 {
		score = float64(time.Now().Unix())
	}
	pipe.ZAdd(ctx, queuePending, redis.Z{
		Score:  score,
		Member: job.ID,
	})

	_, err = pipe.Exec(ctx)
	return err
}

func (q *redisQueue) Pop(ctx context.Context, workerID string) (*types.Job, error) {
	result := q.client.ZPopMin(ctx, queuePending, 1)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	members := result.Val()
	if len(members) == 0 {
		return nil, nil
	}

	jobID := members[0].Member.(string)

	jobData, err := q.client.Get(ctx, jobPrefix+jobID).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get job data: %w", err)
	}

	var job types.Job
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}

	job.Status = "processing"
	job.UpdatedAt = time.Now()

	updatedData, err := json.Marshal(job)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated job: %w", err)
	}

	pipe := q.client.Pipeline()
	pipe.Set(ctx, jobPrefix+jobID, updatedData, 24*time.Hour)
	pipe.HSet(ctx, queueProcessing, jobID, workerID)
	pipe.Set(ctx, workerPrefix+workerID+":current", jobID, 1*time.Hour)

	if _, err := pipe.Exec(ctx); err != nil {
		q.client.ZAdd(ctx, queuePending, redis.Z{
			Score:  float64(job.Priority),
			Member: jobID,
		})
		return nil, fmt.Errorf("failed to update job status: %w", err)
	}

	return &job, nil
}

func (q *redisQueue) Complete(ctx context.Context, jobID string) error {
	jobData, err := q.client.Get(ctx, jobPrefix+jobID).Result()
	if err != nil {
		return fmt.Errorf("failed to get job data: %w", err)
	}

	var job types.Job
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return fmt.Errorf("failed to unmarshal job: %w", err)
	}

	job.Status = "completed"
	job.UpdatedAt = time.Now()

	updatedData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal updated job: %w", err)
	}

	workerID, _ := q.client.HGet(ctx, queueProcessing, jobID).Result()

	pipe := q.client.Pipeline()
	pipe.Set(ctx, jobPrefix+jobID, updatedData, 24*time.Hour)
	pipe.HDel(ctx, queueProcessing, jobID)
	if workerID != "" {
		pipe.Del(ctx, workerPrefix+workerID+":current")
	}

	_, err = pipe.Exec(ctx)
	return err
}

func (q *redisQueue) Fail(ctx context.Context, jobID string, reason string) error {
	jobData, err := q.client.Get(ctx, jobPrefix+jobID).Result()
	if err != nil {
		return fmt.Errorf("failed to get job data: %w", err)
	}

	var job types.Job
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return fmt.Errorf("failed to unmarshal job: %w", err)
	}

	job.Status = "failed"
	job.UpdatedAt = time.Now()
	job.Payload["error"] = reason

	updatedData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal updated job: %w", err)
	}

	workerID, _ := q.client.HGet(ctx, queueProcessing, jobID).Result()

	pipe := q.client.Pipeline()
	pipe.Set(ctx, jobPrefix+jobID, updatedData, 24*time.Hour)
	pipe.HDel(ctx, queueProcessing, jobID)
	pipe.ZAdd(ctx, queueFailed, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: jobID,
	})
	if workerID != "" {
		pipe.Del(ctx, workerPrefix+workerID+":current")
	}

	_, err = pipe.Exec(ctx)
	return err
}

func (q *redisQueue) Retry(ctx context.Context, jobID string) error {
	jobData, err := q.client.Get(ctx, jobPrefix+jobID).Result()
	if err != nil {
		return fmt.Errorf("failed to get job data: %w", err)
	}

	var job types.Job
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return fmt.Errorf("failed to unmarshal job: %w", err)
	}

	job.Status = "pending"
	job.Retries++
	job.UpdatedAt = time.Now()

	updatedData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal updated job: %w", err)
	}

	pipe := q.client.Pipeline()
	pipe.Set(ctx, jobPrefix+jobID, updatedData, 24*time.Hour)
	pipe.ZRem(ctx, queueFailed, jobID)
	pipe.ZAdd(ctx, queuePending, redis.Z{
		Score:  float64(job.Priority - job.Retries*10),
		Member: jobID,
	})

	_, err = pipe.Exec(ctx)
	return err
}

func (q *redisQueue) GetStatus(ctx context.Context, jobID string) (*types.Job, error) {
	jobData, err := q.client.Get(ctx, jobPrefix+jobID).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("job not found")
		}
		return nil, fmt.Errorf("failed to get job data: %w", err)
	}

	var job types.Job
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}

	return &job, nil
}

func (q *redisQueue) GetPending(ctx context.Context) ([]*types.Job, error) {
	jobIDs, err := q.client.ZRange(ctx, queuePending, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get pending jobs: %w", err)
	}

	jobs := make([]*types.Job, 0, len(jobIDs))
	for _, jobID := range jobIDs {
		job, err := q.GetStatus(ctx, jobID)
		if err != nil {
			continue
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

func (q *redisQueue) Close() error {
	return q.client.Close()
}
