package secrets

type VaultService struct {
	Secrets Secrets
}

func NewVaultService(secrets Secrets) *VaultService {
	return &VaultService{
		Secrets: secrets,
	}
}
