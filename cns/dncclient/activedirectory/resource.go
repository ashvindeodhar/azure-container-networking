package activedirectory

import (
	"fmt"
	"regexp"
)

type Resource struct {
	SubscriptionID    string
	ResourceGroupName string
	ProviderNamespace string
	ResourceType      string
	ResourceName      string
}

// a resource id should be in the format
// '/subscriptions/{sub-id}/resourceGroups/{rg-name}/providers/{provider-ns}/{resource-type}/{resource-name}'
// where the resource metadata is case sensitive, but not the standard path segments
const resourceRegex = `^/(?i)subscriptions(?-i)/([^/]*)/(?i)resourceGroups(?-i)/([^/]*)/(?i)providers(?-i)/([^/]*)/([^/]*)/([^/]*)$`

var resourceRegexp = regexp.MustCompile(resourceRegex)

func ParseResource(resourceID string) (Resource, error) {
	submatches := resourceRegexp.FindStringSubmatch(resourceID)
	if len(submatches) != 6 {
		return Resource{}, fmt.Errorf("input '%s' not in format '%s'", resourceID, resourceRegex)
	}
	return Resource{
		SubscriptionID:    submatches[1],
		ResourceGroupName: submatches[2],
		ProviderNamespace: submatches[3],
		ResourceType:      submatches[4],
		ResourceName:      submatches[5],
	}, nil
}
