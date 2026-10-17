package access

import (
	"context"
	"sync"
	"time"
)

func (a *App) reserveFiles(u *User, account string) (func(), error) {
	keys := []string{"gateway", "user:" + u.Workspace + ":" + u.ID, "account:" + account, "workspace:" + u.Workspace}
	limits := []int{a.Config.MaxSFTP, 8, 8, a.Config.MaxSFTP}
	a.mu.Lock()
	for i, k := range keys {
		if a.fileSlots[k] >= limits[i] {
			a.mu.Unlock()
			return nil, fail(429, "sftp_channel_quota", "网关、用户或账号文件通道配额已满")
		}
	}
	for _, k := range keys {
		a.fileSlots[k]++
	}
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			for _, k := range keys {
				a.fileSlots[k]--
				if a.fileSlots[k] == 0 {
					delete(a.fileSlots, k)
				}
			}
			a.mu.Unlock()
		})
	}, nil
}
func (a *App) takeBandwidth(ctx context.Context, u *User, n int64) error {
	key := u.Workspace + ":" + u.ID
	now := time.Now()
	a.mu.Lock()
	start := a.bandwidthNext[key]
	if start.Before(now) {
		start = now
	}
	end := start.Add(time.Duration(float64(n) / float64(a.Config.Bandwidth) * float64(time.Second)))
	a.bandwidthNext[key] = end
	a.mu.Unlock()
	timer := time.NewTimer(time.Until(end))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
