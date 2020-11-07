package activedirectory

import (
	"testing"
)

func TestParseResource(t *testing.T) {
	expected := Resource{
		SubscriptionID:    "some-sub-id",
		ResourceGroupName: "some-rg",
		ProviderNamespace: "Microsoft.SomeThing",
		ResourceType:      "someTypeOfThing",
		ResourceName:      "thing-name",
	}

	tests := []struct {
		name       string
		resourceID string
	}{
		{
			name:       "mixed case path segments",
			resourceID: "/subscriptions/some-sub-id/resourceGroups/some-rg/providers/Microsoft.SomeThing/someTypeOfThing/thing-name",
		},
		{
			name:       "all caps path segments",
			resourceID: "/SUBSCRIPTIONS/some-sub-id/RESOURCEGROUPS/some-rg/PROVIDERS/Microsoft.SomeThing/someTypeOfThing/thing-name",
		},
		{
			name:       "no caps path segments",
			resourceID: "/subscriptions/some-sub-id/resourcegroups/some-rg/providers/Microsoft.SomeThing/someTypeOfThing/thing-name",
		},
	}

	for _, tt := range tests {
		ts := tt
		t.Run(ts.name, func(t *testing.T) {
			res, err := ParseResource(ts.resourceID)
			if err != nil {
				t.Fatalf("did not expect error, got %v", err)
			}
			if res != expected {
				t.Fatalf("expected: %+v, got %v", expected, res)
			}
		})
	}
}
