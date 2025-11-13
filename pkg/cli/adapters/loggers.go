package adapters

import (
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// FuzzingLogger adapts internal logger.Logger for fuzzing package interface.
// This adapter uses the Infow/Debugw/Warnw/Errorw methods with key-value pairs.
type FuzzingLogger struct {
	log *logger.Logger
}

// NewFuzzingLogger creates a new FuzzingLogger adapter.
func NewFuzzingLogger(log *logger.Logger) *FuzzingLogger {
	return &FuzzingLogger{log: log}
}

func (f *FuzzingLogger) Info(msg string, keysAndValues ...interface{}) {
	if f.log != nil {
		f.log.Infow(msg, keysAndValues...)
	}
}

func (f *FuzzingLogger) Debug(msg string, keysAndValues ...interface{}) {
	if f.log != nil {
		f.log.Debugw(msg, keysAndValues...)
	}
}

func (f *FuzzingLogger) Warn(msg string, keysAndValues ...interface{}) {
	if f.log != nil {
		f.log.Warnw(msg, keysAndValues...)
	}
}

func (f *FuzzingLogger) Error(msg string, keysAndValues ...interface{}) {
	if f.log != nil {
		f.log.Errorw(msg, keysAndValues...)
	}
}

// ProtocolLogger adapts internal logger.Logger for protocol package interface.
// This adapter uses the Infow/Debugw/Warnw/Errorw methods with key-value pairs.
type ProtocolLogger struct {
	log *logger.Logger
}

// NewProtocolLogger creates a new ProtocolLogger adapter.
func NewProtocolLogger(log *logger.Logger) *ProtocolLogger {
	return &ProtocolLogger{log: log}
}

func (p *ProtocolLogger) Info(msg string, keysAndValues ...interface{}) {
	if p.log != nil {
		p.log.Infow(msg, keysAndValues...)
	}
}

func (p *ProtocolLogger) Debug(msg string, keysAndValues ...interface{}) {
	if p.log != nil {
		p.log.Debugw(msg, keysAndValues...)
	}
}

func (p *ProtocolLogger) Warn(msg string, keysAndValues ...interface{}) {
	if p.log != nil {
		p.log.Warnw(msg, keysAndValues...)
	}
}

func (p *ProtocolLogger) Error(msg string, keysAndValues ...interface{}) {
	if p.log != nil {
		p.log.Errorw(msg, keysAndValues...)
	}
}

// BoileauLogger adapts internal logger.Logger for Boileau package interface.
// This adapter uses the Infow/Debugw/Warnw/Errorw methods with key-value pairs.
type BoileauLogger struct {
	log *logger.Logger
}

// NewBoileauLogger creates a new BoileauLogger adapter.
func NewBoileauLogger(log *logger.Logger) *BoileauLogger {
	return &BoileauLogger{log: log}
}

func (b *BoileauLogger) Info(msg string, keysAndValues ...interface{}) {
	if b.log != nil {
		b.log.Infow(msg, keysAndValues...)
	}
}

func (b *BoileauLogger) Debug(msg string, keysAndValues ...interface{}) {
	if b.log != nil {
		b.log.Debugw(msg, keysAndValues...)
	}
}

func (b *BoileauLogger) Warn(msg string, keysAndValues ...interface{}) {
	if b.log != nil {
		b.log.Warnw(msg, keysAndValues...)
	}
}

func (b *BoileauLogger) Error(msg string, keysAndValues ...interface{}) {
	if b.log != nil {
		b.log.Errorw(msg, keysAndValues...)
	}
}
