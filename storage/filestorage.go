package storage

import (
	"io/ioutil"
	"path"
)

type FileStorage struct {
	folderPath string
}

func NewFileStorage(folder string) Storage {
	return &FileStorage{
		folderPath: folder,
	}
}

func (f *FileStorage) Store(e StorageEntry) error {
	fullPath := path.Join(f.folderPath, e.Title)
	return ioutil.WriteFile(fullPath, e.Body, 0600)
}

func (f *FileStorage) Load(title string) (StorageEntry, error) {
	fullPath := path.Join(f.folderPath, title)
	b, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return StorageEntry{}, err
	}
	return StorageEntry{
		Title: title,
		Body:  b,
	}, nil
}

func (f *FileStorage) List() ([]StorageEntry, error) {
	files, err := ioutil.ReadDir(f.folderPath)
	if err != nil {
		return nil, err
	}

	entries := make([]StorageEntry, 0, len(files))

	for _, file := range files {
		if !file.IsDir() {
			entry, err := f.Load(file.Name())
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}
