package vmm

import "testing"

func TestHVReturnString(t *testing.T) {
	tests := []struct {
		ret  uint32
		want string
	}{
		{hvSuccess, "HV_SUCCESS"},
		{hvError, "HV_ERROR"},
		{hvBusy, "HV_BUSY"},
		{hvBadArgument, "HV_BAD_ARGUMENT"},
		{hvIllegalGuestState, "HV_ILLEGAL_GUEST_STATE"},
		{hvNoResources, "HV_NO_RESOURCES"},
		{hvNoDevice, "HV_NO_DEVICE"},
		{hvDenied, "HV_DENIED (check hypervisor entitlement)"},
		{hvUnsupported, "HV_UNSUPPORTED"},
		{0xdeadbeef, "hv_return_t(0xdeadbeef)"},
	}

	for _, test := range tests {
		if got := hvReturnString(test.ret); got != test.want {
			t.Errorf("hvReturnString(%#x) = %q, want %q", test.ret, got, test.want)
		}
	}
}
