package dashboard

import "testing"

func TestMemorySliderKeepsHostBounds(t *testing.T) {
	for _, value := range []int{32, 512, 16384, 32768} {
		slider := newMemorySlider(65, 16384, value)
		if slider.Min != 65 || slider.Max != 16384 || slider.Value != clampInt(value, 65, 16384) {
			t.Fatalf("initial value %d: unexpected slider %+v", value, slider)
		}
		slider.Set(32768)
		slider.Adjust(1)
		if slider.Value != 16384 {
			t.Fatalf("slider exceeded host memory: %+v", slider)
		}
	}
}

func TestMemorySliderMouseReachesHostMaximum(t *testing.T) {
	slider := newMemorySlider(65, 16384, 512)
	slider.SetFraction(39, 40)
	if slider.Value != slider.Max {
		t.Fatalf("right endpoint = %d, want %d", slider.Value, slider.Max)
	}
	slider.SetFraction(0, 40)
	if slider.Value != slider.Min {
		t.Fatalf("left endpoint = %d, want %d", slider.Value, slider.Min)
	}
}
