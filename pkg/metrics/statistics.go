package metrics

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"
	"github.com/openshift/ingress-node-firewall/pkg/failsaferules"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	controllerruntimemetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var metricAllowCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricINFNamespace,
	Subsystem: MetricINFSubsystemNode,
	Name:      "packet_allow_total",
	Help:      "The number of packets which results in an allow IP packet result",
})

var metricAllowBytesCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricINFNamespace,
	Subsystem: MetricINFSubsystemNode,
	Name:      "packet_allow_bytes",
	Help:      "The number of bytes for packets which results in an allow IP packet result",
})

var metricDenyCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricINFNamespace,
	Subsystem: MetricINFSubsystemNode,
	Name:      "packet_deny_total",
	Help:      "The number of packets which results in a deny IP packet result",
})

var metricDenyBytesCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricINFNamespace,
	Subsystem: MetricINFSubsystemNode,
	Name:      "packet_deny_bytes",
	Help:      "The number of bytes for packets which results in an deny IP packet result",
})

const (
	MetricINFNamespace     = "ingressnodefirewall"
	MetricINFSubsystemNode = "node"
)

// GetPrometheusStatisticNames returns all statistic metric names - to aid testing only.
func GetPrometheusStatisticNames() []string {
	return []string{
		MetricINFNamespace + "_" + MetricINFSubsystemNode + "_" + "packet_allow_total",
		MetricINFNamespace + "_" + MetricINFSubsystemNode + "_" + "packet_allow_bytes",
		MetricINFNamespace + "_" + MetricINFSubsystemNode + "_" + "packet_deny_total",
		MetricINFNamespace + "_" + MetricINFSubsystemNode + "_" + "packet_deny_bytes",
	}
}

type Statistics struct {
	//regOnce ensures that we only register metrics once otherwise panic may occur
	regOnce sync.Once
	mapWG   sync.WaitGroup
	//mu controls access to isMapPollActive/mapStopCh
	mapStopCh       chan struct{}
	isMapPollActive bool
	pollPeriod      time.Duration
}

func NewStatistics(pollPeriod string) (*Statistics, error) {
	i, err := strconv.Atoi(pollPeriod)
	if err != nil {
		return nil, fmt.Errorf("failed to convert %q to integer: %v", pollPeriod, err)
	}
	return &Statistics{pollPeriod: time.Duration(i) * time.Second}, nil
}

func (m *Statistics) Register() {
	m.regOnce.Do(func() {
		controllerruntimemetrics.Registry.MustRegister(metricAllowCount)
		controllerruntimemetrics.Registry.MustRegister(metricAllowBytesCount)
		controllerruntimemetrics.Registry.MustRegister(metricDenyCount)
		controllerruntimemetrics.Registry.MustRegister(metricDenyBytesCount)
	})
}

func (m *Statistics) StartPoll(statsMap *ebpf.Map) {
	if m.isMapPollActive {
		log.Println("Metrics are already being polled")
		return
	}
	m.mapWG.Add(1)
	m.mapStopCh = make(chan struct{})
	m.isMapPollActive = true

	go func() {
		defer m.mapWG.Done()
		updateMetrics(m.mapStopCh, statsMap, m.pollPeriod)
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
	var allowCount, allowBytesCount, denyCount, denyBytesCount, result uint64
	var ruleStats []nodefwloader.BpfRuleStatisticsSt
	var ok bool
	var err error

	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			allowCount, allowBytesCount, denyCount, denyBytesCount = 0, 0, 0, 0

			for rule := 1; rule < failsaferules.MAX_INGRESS_RULES; rule++ {
				if err = statsMap.Lookup(uint32(rule), &ruleStats); err != nil {
					log.Printf("Failed to lookup statistics for rule %d: %v\n", rule, err)
					continue
				}

				for _, stat := range ruleStats {
					if result, ok = addUInt64(stat.AllowStats.Packets, allowCount); !ok {
						log.Println("Overflow occurred during addition of allow packet statistic")
					} else {
						allowCount = result
					}

					if result, ok = addUInt64(stat.AllowStats.Bytes, allowBytesCount); !ok {
						log.Println("Overflow occurred during addition of allow byte statistic")
					} else {
						allowBytesCount = result
					}

					if result, ok = addUInt64(stat.DenyStats.Packets, denyCount); !ok {
						log.Println("Overflow occurred during addition of deny packet statistic")
					} else {
						denyCount = result
					}

					if result, ok = addUInt64(stat.DenyStats.Bytes, denyBytesCount); !ok {
						log.Println("Overflow occurred during addition of deny byte statistic")
					} else {
						denyBytesCount = result
					}
				}
			}
			metricAllowCount.Set(float64(allowCount))
			metricAllowBytesCount.Set(float64(allowBytesCount))
			metricDenyCount.Set(float64(denyCount))
			metricDenyBytesCount.Set(float64(denyBytesCount))
		case <-stopCh:
			log.Println("Stopped node metric updates")
			return
		}
	}
}

// addUInt64 performs op and checks for overflow. Returns value, and true for success.
func addUInt64(a, b uint64) (uint64, bool) {
	c := a + b
	if a == 0 || b == 0 {
		return c, true
	}
	if c > a && c > b {
		return c, true
	}
	// overflow
	return c, false
}
