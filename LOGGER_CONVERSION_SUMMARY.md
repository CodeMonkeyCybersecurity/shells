# Logger Conversion Summary

## Overview
This document summarizes the locations where we need to convert from direct log usage or zap.Logger to the internal logger package.

## Files Using Direct log.* Methods (Need Conversion)
These files are using `log.Debug()`, `log.Error()`, `log.Info()`, `log.Warn()` directly on the logger variable:

### Command Files (cmd/)
1. `/opt/shells/cmd/root.go` - Uses log.Error() directly
2. `/opt/shells/cmd/scanner_executor.go` - Multiple log.Error(), log.Debug(), log.Warn() calls
3. `/opt/shells/cmd/rumble.go` - Direct log usage
4. `/opt/shells/cmd/schedule.go` - log.Info() calls
5. `/opt/shells/cmd/fuzz.go` - Direct log usage
6. `/opt/shells/cmd/deploy.go` - Direct log usage
7. `/opt/shells/cmd/boileau.go` - Direct log usage
8. `/opt/shells/cmd/protocol.go` - Direct log usage
9. `/opt/shells/cmd/scan.go` - Extensive log.Info(), log.Error(), log.Debug(), log.Warn() usage
10. `/opt/shells/cmd/workflow.go` - Direct log usage
11. `/opt/shells/cmd/config.go` - log.Info() calls

## Files Using zap.Logger (Need Conversion)
These files are using `*zap.Logger` directly instead of the internal logger package:

### Package Files (pkg/)
1. `/opt/shells/pkg/auth/discovery/portscanner.go`
2. `/opt/shells/pkg/auth/discovery/org_correlation_module.go`
3. `/opt/shells/pkg/discovery/mail_analyzer.go`
4. `/opt/shells/pkg/discovery/service_classifier.go`
5. `/opt/shells/pkg/auth/crawlers.go`
6. `/opt/shells/pkg/auth/discovery_engine.go`
7. `/opt/shells/pkg/correlation/clients.go`
8. `/opt/shells/pkg/correlation/organization.go`
9. `/opt/shells/pkg/scanners/secrets/trufflehog.go`
10. `/opt/shells/pkg/correlation/risk_calculator.go`
11. `/opt/shells/pkg/correlation/timeline_analyzer.go`
12. `/opt/shells/pkg/correlation/exploit_chainer.go`
13. `/opt/shells/pkg/ml/techstack.go`
14. `/opt/shells/pkg/ml/predictor.go`

## Conversion Required

### For Direct log.* Usage
Replace patterns like:
- `log.Error("message", "key", value)` → `log.LogError(ctx, err, "operation", "key", value)`
- `log.Info("message", "key", value)` → `log.Infow("message", "key", value)`
- `log.Debug("message", "key", value)` → `log.Debugw("message", "key", value)`
- `log.Warn("message", "key", value)` → `log.Warnw("message", "key", value)`

### For zap.Logger Usage
Replace:
- `logger *zap.Logger` → `logger *logger.Logger`
- Import `"go.uber.org/zap"` → Import `"github.com/CodeMonkeyCybersecurity/shells/internal/logger"`
- `zap.NewProduction()` → `logger.New(config.LoggerConfig{...})`
- Direct zap methods → Use internal logger methods with enhanced context

## Enhanced Logging Methods Available
The internal logger provides enhanced methods for:
- Context-aware logging: `WithContext(ctx)`
- Security events: `LogSecurityEvent()`, `LogVulnerability()`
- Performance tracking: `LogDuration()`, `LogSlowOperation()`
- HTTP/Network: `LogHTTPRequest()`
- Database operations: `LogDatabaseOperation()`
- Scan progress: `LogScanProgress()`, `LogDiscoveryEvent()`
- Error handling: `LogError()`, `LogPanic()`
- OpenTelemetry integration: Automatic span correlation

## Priority
1. Start with cmd/ files as they are entry points
2. Move to pkg/ files that are core to the scanning functionality
3. Ensure context is properly propagated for tracing