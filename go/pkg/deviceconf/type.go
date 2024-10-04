package deviceconf

type Config interface {
	MergeSpoc(Config) Config
}
