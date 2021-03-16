package discovery

type Service interface {
	Register(advProtocol string, advHost string, advPort string) error
	Deregister() error
}
