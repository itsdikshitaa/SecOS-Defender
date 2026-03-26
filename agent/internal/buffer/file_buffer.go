package buffer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/therayyanawaz/secos-defender/agent/internal/api"
)

type FileBuffer struct {
	path string
	mu   sync.Mutex
}

func New(path string) *FileBuffer {
	return &FileBuffer{path: path}
}

func (b *FileBuffer) ensureDir() error {
	return os.MkdirAll(filepath.Dir(b.path), 0o755)
}

func (b *FileBuffer) Load() ([]api.NormalizedEvent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ensureDir(); err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []api.NormalizedEvent{}, nil
		}
		return nil, err
	}
	if len(contents) == 0 {
		return []api.NormalizedEvent{}, nil
	}
	var events []api.NormalizedEvent
	if err := json.Unmarshal(contents, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func (b *FileBuffer) Replace(events []api.NormalizedEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ensureDir(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.path, body, 0o644)
}

func (b *FileBuffer) Append(events []api.NormalizedEvent) error {
	current, err := b.Load()
	if err != nil {
		return err
	}
	current = append(current, events...)
	return b.Replace(current)
}

func (b *FileBuffer) Size() (int, error) {
	events, err := b.Load()
	if err != nil {
		return 0, err
	}
	return len(events), nil
}
