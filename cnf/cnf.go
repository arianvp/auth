package cnf

type Confirmer[T any] interface {
	Confirm(*T) error
}
