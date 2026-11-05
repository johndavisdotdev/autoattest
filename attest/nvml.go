package attest

import (
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

// CCState is the system-wide Confidential Compute state reported by the driver.
type CCState struct {
	CCFeatureEnabled bool
	Production       bool // environment is PROD (not SIM)
	DevToolsMode     bool
	GPUsReady        bool
	CPUCaps          string
	GPUsCCCapable    bool
	MultiGPUMode     string
}

// GPUEvidence is the raw attestation material for one GPU.
type GPUEvidence struct {
	Info         GPUInfo
	Report       []byte // SPDM GET_MEASUREMENTS request + signed response
	CertChainPEM []byte // attestation certificate chain, leaf first
}

// GPUSource abstracts the GPU driver so the verification logic is testable.
type GPUSource interface {
	CCState() (CCState, error)
	Evidence(nonce [32]byte) ([]GPUEvidence, error)
	Close() error
}

// NVMLSource reads CC state and attestation evidence through NVML.
type NVMLSource struct {
	lib nvml.Interface
}

// OpenNVML initialises NVML. Callers must Close the returned source.
func OpenNVML() (*NVMLSource, error) {
	lib := nvml.New()
	if ret := lib.Init(); ret != nvml.SUCCESS {
		return nil, fmt.Errorf("nvml init: %v", nvml.ErrorString(ret))
	}
	return &NVMLSource{lib: lib}, nil
}

func (s *NVMLSource) Close() error {
	if ret := s.lib.Shutdown(); ret != nvml.SUCCESS {
		return fmt.Errorf("nvml shutdown: %v", nvml.ErrorString(ret))
	}
	return nil
}

func nvmlErr(op string, ret nvml.Return) error {
	return fmt.Errorf("%s: %s", op, nvml.ErrorString(ret))
}

func (s *NVMLSource) CCState() (CCState, error) {
	var st CCState

	settings, ret := s.lib.SystemGetConfComputeSettings()
	if ret != nvml.SUCCESS {
		// Fall back to the older API on drivers without the v1 settings struct.
		state, ret2 := s.lib.SystemGetConfComputeState()
		if ret2 != nvml.SUCCESS {
			return st, nvmlErr("nvmlSystemGetConfComputeState", ret2)
		}
		settings.Environment = state.Environment
		settings.CcFeature = state.CcFeature
		settings.DevToolsMode = state.DevToolsMode
		settings.MultiGpuMode = nvml.CC_SYSTEM_MULTIGPU_NONE
	}
	st.CCFeatureEnabled = settings.CcFeature == nvml.CC_SYSTEM_FEATURE_ENABLED
	st.Production = settings.Environment == nvml.CC_SYSTEM_ENVIRONMENT_PROD
	st.DevToolsMode = settings.DevToolsMode == nvml.CC_SYSTEM_DEVTOOLS_MODE_ON
	switch settings.MultiGpuMode {
	case nvml.CC_SYSTEM_MULTIGPU_NONE:
		st.MultiGPUMode = "None"
	case nvml.CC_SYSTEM_MULTIGPU_PROTECTED_PCIE:
		st.MultiGPUMode = "Protected PCIe"
	case nvml.CC_SYSTEM_MULTIGPU_NVLE:
		st.MultiGPUMode = "NVLE"
	default:
		st.MultiGPUMode = fmt.Sprintf("unknown(%d)", settings.MultiGpuMode)
	}

	caps, ret := s.lib.SystemGetConfComputeCapabilities()
	if ret != nvml.SUCCESS {
		return st, nvmlErr("nvmlSystemGetConfComputeCapabilities", ret)
	}
	switch caps.CpuCaps {
	case nvml.CC_SYSTEM_CPU_CAPS_INTEL_TDX:
		st.CPUCaps = "INTEL TDX"
	case nvml.CC_SYSTEM_CPU_CAPS_AMD_SEV:
		st.CPUCaps = "AMD SEV"
	case nvml.CC_SYSTEM_CPU_CAPS_AMD_SEV_SNP:
		st.CPUCaps = "AMD SEV-SNP"
	case nvml.CC_SYSTEM_CPU_CAPS_AMD_SNP_VTOM:
		st.CPUCaps = "AMD SNP vTOM"
	default:
		st.CPUCaps = "None"
	}
	st.GPUsCCCapable = caps.GpusCaps == nvml.CC_SYSTEM_GPUS_CC_CAPABLE

	ready, ret := s.lib.SystemGetConfComputeGpusReadyState()
	if ret != nvml.SUCCESS {
		return st, nvmlErr("nvmlSystemGetConfComputeGpusReadyState", ret)
	}
	st.GPUsReady = ready == nvml.CC_ACCEPTING_CLIENT_REQUESTS_TRUE
	return st, nil
}

func (s *NVMLSource) Evidence(nonce [32]byte) ([]GPUEvidence, error) {
	count, ret := s.lib.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, nvmlErr("nvmlDeviceGetCount", ret)
	}
	driver, _ := s.lib.SystemGetDriverVersion()

	out := make([]GPUEvidence, 0, count)
	for i := range count {
		dev, ret := s.lib.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, nvmlErr(fmt.Sprintf("gpu %d: get handle", i), ret)
		}
		info := GPUInfo{Index: i, DriverVersion: driver}
		info.UUID, _ = dev.GetUUID()
		info.Name, _ = dev.GetName()
		info.VBIOSVersion, _ = dev.GetVbiosVersion()
		arch, ret := dev.GetArchitecture()
		if ret != nvml.SUCCESS {
			return nil, nvmlErr(fmt.Sprintf("gpu %d: get architecture", i), ret)
		}
		info.Arch = archName(arch)

		report := nvml.ConfComputeGpuAttestationReport{Nonce: nonce}
		if ret := dev.GetConfComputeGpuAttestationReport(&report); ret != nvml.SUCCESS {
			return nil, nvmlErr(fmt.Sprintf("gpu %d: get attestation report", i), ret)
		}
		cert, ret := dev.GetConfComputeGpuCertificate()
		if ret != nvml.SUCCESS {
			return nil, nvmlErr(fmt.Sprintf("gpu %d: get certificate chain", i), ret)
		}
		if int(report.AttestationReportSize) > len(report.AttestationReport) ||
			int(cert.AttestationCertChainSize) > len(cert.AttestationCertChain) {
			return nil, fmt.Errorf("gpu %d: driver returned oversized evidence", i)
		}
		out = append(out, GPUEvidence{
			Info:         info,
			Report:       append([]byte(nil), report.AttestationReport[:report.AttestationReportSize]...),
			CertChainPEM: append([]byte(nil), cert.AttestationCertChain[:cert.AttestationCertChainSize]...),
		})
	}
	return out, nil
}

// archName maps NVML architectures to the names NRAS expects.
func archName(a nvml.DeviceArchitecture) string {
	switch a {
	case nvml.DEVICE_ARCH_HOPPER:
		return "HOPPER"
	case nvml.DEVICE_ARCH_BLACKWELL:
		return "BLACKWELL"
	default:
		return fmt.Sprintf("UNSUPPORTED(%d)", a)
	}
}
