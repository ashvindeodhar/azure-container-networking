package activedirectory

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/adal"
)

const tokenRefreshTimeout = time.Minute

// A TokenFetcher fetches OAuth token against a specific resource.
type TokenFetcher interface {
	GetOAuthToken(ctx context.Context, resource string) (string, error)
}

// aadTokenFetcher is used to build a service principal token for accessing different resources.
// By default, if none of the fields are assigned, it will use the system assigned identity.
// Otherwise, it will return a token for the ClientID provided.
type AADTokenFetcher struct {
	ClientID string
}

// GetOAuthToken returns a freshly fetched OAuth token for the given service principal
func (f *AADTokenFetcher) GetOAuthToken(ctx context.Context, resource string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, tokenRefreshTimeout)
	defer cancel()
	spt, err := f.getServicePrincipalToken(resource)
	if err != nil {
		return "", fmt.Errorf("Failed to get Service Principle token. Error: %v", err)
	}

	if err := spt.RefreshWithContext(ctx); err != nil {
		return "", fmt.Errorf("Could not get OAuthToken: %v", err)
	}
	return spt.OAuthToken(), nil
}

// getServicePrincipalToken returns a token for the specified resource.
// The token returned may need to be refreshed before use.
func (f *AADTokenFetcher) getServicePrincipalToken(resource string) (*adal.ServicePrincipalToken, error) {
	msiEndpoint, _ := adal.GetMSIVMEndpoint() // error is always nil

	switch {
	case f.ClientID != "":
		return adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, resource, f.ClientID)
	default:
		return adal.NewServicePrincipalTokenFromMSI(msiEndpoint, resource)
	}
}
