package metrics

import (
	"log"
	"sync"
	"time"

	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	controllerruntimemetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var metricAllowPacketCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricINFNamespace,
	Subsystem: metricINFSubsystemNode,
	Name:      "packet_allow_total",
	Help:      "The number of packets which results in an allow IP packet result",
})

var metricAllowPacketBytes = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricINFNamespace,
	Subsystem: metricINFSubsystemNode,
	Name:      "packet_allow_bytes",
	Help:      "The number of bytes for packets which results in an allow IP packet result",
})

var metricDenyPacketCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricINFNamespace,
	Subsystem: metricINFSubsystemNode,
	Name:      "packet_deny_total",
	Help:      "The number of packets which results in a deny IP packet result",
})

var metricDenyPacketBytes = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: metricINFNamespace,
	Subsystem: metricINFSubsystemNode,
	Name:      "packet_deny_bytes",
	Help:      "The number of bytes for packets which results in an deny IP packet result",
})

const (
	maxRules               = 100 // Max number of rules per sourceCIDRs
	metricINFNamespace     = "ingressnodefirewall"
	metricINFSubsystemNode = "node"
)

type Statistics struct {
	//regOnce ensures that we only register metrics once otherwise panic may occur
	regOnce sync.Once
	mapWG   sync.WaitGroup
	//mu controls access to isMapPollActive/mapStopCh
	mapStopCh       chan struct{}
	isMapPollActive bool
}

func NewStatistics() *Statistics {
	return &Statistics{}
}

func (m *Statistics) Register() {
	m.regOnce.Do(func() {
		controllerruntimemetrics.Registry.MustRegister(metricAllowPacketCount)
		controllerruntimemetrics.Registry.MustRegister(metricAllowPacketBytes)
		controllerruntimemetrics.Registry.MustRegister(metricDenyPacketCount)
		controllerruntimemetrics.Registry.MustRegister(metricDenyPacketBytes)
	})
}

func (m *Statistics) StartPoll(statsMap *ebpf.Map, period time.Duration) {
	if m.isMapPollActive {
		log.Println("Metrics are already being polled")
		return
	}
	m.mapWG.Add(1)
	m.mapStopCh = make(chan struct{})
	m.isMapPollActive = true

	go func() {
		defer m.mapWG.Done()
		updateMetrics(m.mapStopCh, statsMap, period)
		m.isMapPollActive = false
	}()
}

func (m *Statistics) StopPoll() {
	if !m.isMapPollActive {
		return
	}
	close(m.mapStopCh)
	m.mapWG.Wait()
}

func updateMetrics(stopCh <-chan struct{}, statsMap *ebpf.Map, period time.Duration) {
	log.Println("Starting node metrics updater. Metrics will be polled periodically and presented as prometheus metrics")
	ticker := time.NewTicker(period)
	var allowPackets, allowBytes, denyPackets, denyBytes, result float64
	var ruleStats []nodefwloader.BpfRuleStatisticsSt
	var ok bool
	var err error

	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			allowPackets, allowBytes, denyPackets, denyBytes, result = 0, 0, 0, 0, 0

			for rule := 0; rule < maxRules; rule++ {
				if err = statsMap.Lookup(uint32(rule), &ruleStats); err != nil {
					log.Printf("Failed to lookup statistics for rule %d: %v\n", rule, err)
					continue
				}

				for _, stat := range ruleStats {
					if result, ok = addUInt64Float64(stat.AllowStats.Packets, allowPackets); !ok {
						log.Println("Overflow occurred during addition of allow packet statistic")
					} else {
						allowPackets = result
					}

					if result, ok = addUInt64Float64(stat.AllowStats.Bytes, allowBytes); !ok {
						log.Println("Overflow occurred during addition of allow byte statistic")
					} else {
						allowBytes = result
					}

					if result, ok = addUInt64Float64(stat.DenyStats.Packets, denyPackets); !ok {
						log.Println("Overflow occurred during addition of deny packet statistic")
					} else {
						denyPackets = result
					}

					if result, ok = addUInt64Float64(stat.DenyStats.Bytes, denyBytes); !ok {
						log.Println("Overflow occurred during addition of deny byte statistic")
					} else {
						denyBytes = result
					}
				}
			}
			metricAllowPacketCount.Set(allowPackets)
			metricAllowPacketBytes.Set(allowBytes)
			metricDenyPacketCount.Set(denyPackets)
			metricDenyPacketBytes.Set(denyBytes)
		case <-stopCh:
			log.Println("Stopped node metric updates")
			return
		}
	}
}

//addUInt64 performs op and checks for overflow. Returns value, and true for success.
func addUInt64Float64(a uint64, b float64) (float64, bool) {
	c := float64(a) + b
	if a == 0 || b == 0 {
		return c, true
	}
	if c > float64(a) && c > b {
		return c, true
	}
	// overflow
	return c, false
}
