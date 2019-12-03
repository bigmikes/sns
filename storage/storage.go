package storage

type StorageEntry struct {
	Title string
	Body  []byte
}

type Storage interface {
	Store(e StorageEntry) error
	Load(title string) (StorageEntry, error)
	List() ([]StorageEntry, error)
}
