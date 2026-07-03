package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	numWorkers    = 8
	perJobTimeout = 3 * time.Second
)

// Orchestrator runs a set of category scanners against an Env and streams the
// per-artifact results over a channel.
type Orchestrator struct {
	env  *Env
	cats []Scanner
}

// NewOrchestrator builds an orchestrator over the given categories.
func NewOrchestrator(env *Env, cats ...Scanner) *Orchestrator {
	return &Orchestrator{env: env, cats: cats}
}

// Categories returns each registered category's metadata, in registration order.
func (o *Orchestrator) Categories() []CategoryMeta {
	metas := make([]CategoryMeta, 0, len(o.cats))
	for _, c := range o.cats {
		metas = append(metas, c.Meta())
	}
	return metas
}

// Env exposes the environment (the tailer and headless collector reuse it).
func (o *Orchestrator) Env() *Env { return o.env }

// Artifacts returns every artifact applicable to the detected distro, in
// category-then-declaration order — the skeleton the TUI paints before results
// arrive.
func (o *Orchestrator) Artifacts() []Artifact { return o.artifacts() }

// RunArtifact runs a single artifact by ID through the same per-job timeout and
// panic recovery as the pooled scan (runOne), returning the result and whether
// the artifact was found. Used by the TUI's periodic refresh so an out-of-band
// rescan can't hang or crash the program.
func (o *Orchestrator) RunArtifact(ctx context.Context, id ArtifactID) (ScanResult, bool) {
	for _, a := range o.artifacts() {
		if a.ID == id {
			return o.runOne(ctx, a), true
		}
	}
	return ScanResult{}, false
}

// artifacts gathers every artifact applicable to the detected distro family.
func (o *Orchestrator) artifacts() []Artifact {
	var arts []Artifact
	for _, c := range o.cats {
		for _, a := range c.Artifacts(o.env) {
			if a.Distros.Matches(o.env.Distro) {
				arts = append(arts, a)
			}
		}
	}
	return arts
}

// Scan fans every artifact out across a bounded worker pool and streams results
// on the returned channel, which is closed once all artifacts finish (or ctx is
// cancelled). One slow or panicking artifact cannot stall or crash the pool.
//
// Exactly one goroutine closes out (after all workers drain), so the TUI's
// channel→Cmd bridge sees a clean close and stops re-arming.
func (o *Orchestrator) Scan(ctx context.Context) <-chan ScanResult {
	arts := o.artifacts()
	jobs := make(chan Artifact)
	out := make(chan ScanResult)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			for a := range jobs {
				select {
				case out <- o.runOne(ctx, a):
				case <-ctx.Done():
					return
				}
			}
		})
	}

	go func() {
		defer close(jobs)
		for _, a := range arts {
			select {
			case jobs <- a:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// runOne executes one artifact scan with a per-job timeout and panic recovery,
// so a bad scanner degrades to a CRIT result rather than taking down the pool.
// Category, Artifact, and Elapsed are always stamped, even on panic.
func (o *Orchestrator) runOne(ctx context.Context, a Artifact) (res ScanResult) {
	start := time.Now() // wall-clock timing, independent of the anomaly clock
	jobCtx, cancel := context.WithTimeout(ctx, perJobTimeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			res = ScanResult{
				Health:  HealthCrit,
				Summary: "scanner panicked",
				Err:     fmt.Errorf("panic in %s scan: %v", a.ID, r),
			}
		}
		res.Category = a.Category
		res.Artifact = a.ID
		res.Elapsed = time.Since(start)
	}()

	res = a.Scan(jobCtx, o.env)
	return res
}
