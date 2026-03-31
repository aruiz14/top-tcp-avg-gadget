package main

import (
	"fmt"
	"net"
	"time"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

const (
	secondsPerDay          = 24 * 60 * 60
	filterOperatorPriority = 9000
	cliOperatorPriority    = 10001 // from https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.50.1/pkg/operators/cli/clioperator.go#L47
)

func getSourceFields(ds api.DataSource) sourceFields {
	return sourceFields{
		mntnsId:     mustGetField(ds, "_mntns_id"),
		pid:         mustGetField(ds, "_pid"),
		comm:        mustGetField(ds, "_comm"),
		src:         mustGetField(ds, "_src"),
		dst:         mustGetField(ds, "_dst"),
		ts:          mustGetField(ds, "_ts"),
		sentRaw:     mustGetField(ds, "_sent_raw"),
		receivedRaw: mustGetField(ds, "_recv_raw"),
	}
}

func getEnrichedFields(ds api.DataSource) (res *enrichedFields) {
	// enrichedFields are dynamically added and must be retrieved lazily, which could fail in some environments
	defer func() {
		if err := recover(); err != nil {
			api.Warn("Cannot get enriched fields: %v", err)
			res = nil
		}
	}()
	return &enrichedFields{
		k8sNode:          mustGetField(ds, "k8s.node"),
		k8sNamespace:     mustGetField(ds, "k8s.namespace"),
		k8sPodName:       mustGetField(ds, "k8s.podName"),
		k8sContainerName: mustGetField(ds, "k8s.containerName"),
		k8sPodLabels:     mustGetField(ds, "k8s.podLabels"),
	}
}

func getExportedFields(ds api.DataSource) exportedFields {
	return exportedFields{
		pid:         mustAddField(ds, "pid", api.Kind_Uint32),
		comm:        mustAddField(ds, "comm", api.Kind_String),
		src:         mustAddField(ds, "src", api.Kind_String),
		dst:         mustAddField(ds, "dst", api.Kind_String),
		sentRate:    mustAddField(ds, "sent_rate_avg", api.Kind_String),
		recvRate:    mustAddField(ds, "recv_rate_avg", api.Kind_String),
		total:       mustAddField(ds, "total", api.Kind_String),
		proj24:      mustAddField(ds, "proj_24h", api.Kind_String),
		proj24Bytes: mustAddField(ds, "_proj_24h_bytes", api.Kind_Uint64),
	}
}

type statsEntry struct {
	FirstSeen time.Time
	SentRaw   uint64
	RecvRaw   uint64

	// Cached raw structs to recreate the row when idle
	MntNsID uint64
	Pid     uint32
	Comm    string
	Src     string
	Dst     string

	// Enriched fields, we need to keep them to be able to repopulate them on synthetic entries
	k8sNode, k8sNamespace, k8sPodName, k8sContainerName, k8sPodLabels string
}

func (s *statsEntry) id() string {
	return fmt.Sprintf("%d-%d-%s-%s", s.MntNsID, s.Pid, s.Src, s.Dst)
}

// sourceFields are fields defined directly from kernel-space, so they are read-only for this program.
// in order to produce any modification (like artificially emitting entries not already present in the dataArray)
// we need to create new user-space fields and write to them instead (see exportedFields)
type sourceFields struct {
	// map fields from ip_key_t struct
	mntnsId  uint64Field
	pid      uint32Field
	comm     stringField
	src, dst bytesField

	// map fields from traffic_t struct
	ts          uint64Field
	sentRaw     uint64Field
	receivedRaw uint64Field
}

func (f sourceFields) newEntryFrom(data api.Data) (*statsEntry, error) {
	ts, err := getSampleTimestamp(data, f)
	if err != nil {
		return nil, err
	}
	mntns, err := f.mntnsId.Uint64(data)
	if err != nil {
		return nil, err
	}
	pid, err := f.pid.Uint32(data)
	if err != nil {
		return nil, err
	}
	comm, err := f.comm.String(data, 256)
	if err != nil {
		return nil, err
	}
	srcIP, err := getIPFromField(data, f.src)
	if err != nil {
		return nil, err
	}
	dstIP, err := getIPFromField(data, f.dst)
	if err != nil {
		return nil, err
	}
	return &statsEntry{
		FirstSeen: ts,
		MntNsID:   mntns,
		Pid:       pid,
		Comm:      comm,
		Src:       srcIP,
		Dst:       dstIP,
	}, nil
}

func (f sourceFields) increaseCounters(data api.Data, s *statsEntry) error {
	sentRaw, err := f.sentRaw.Uint64(data)
	if err != nil {
		return err
	}
	recvRaw, err := f.receivedRaw.Uint64(data)
	if err != nil {
		return err
	}

	s.SentRaw += sentRaw
	s.RecvRaw += recvRaw

	return nil
}

type enrichedFields struct {
	// unlike "sourceFields", which are emitted from the kernel/BPF program, and backed by "C-memory"
	// these fields are generated completely on user-space, from inspektor-gadget operators, so they can also write to them
	k8sNode          stringFieldWriter
	k8sNamespace     stringFieldWriter
	k8sPodName       stringFieldWriter
	k8sContainerName stringFieldWriter
	k8sPodLabels     stringFieldWriter
}

// saveEnrichedData saves certain fields from a data entry into the provided statsEntry
func (f *enrichedFields) saveEnrichedData(data api.Data, state *statsEntry) (err error) {
	if f == nil {
		return nil
	}
	state.k8sNode, err = f.k8sNode.String(data, 64)
	if err != nil {
		return err
	}
	state.k8sNamespace, err = f.k8sNamespace.String(data, 64)
	if err != nil {
		return err
	}
	state.k8sPodName, err = f.k8sPodName.String(data, 64)
	if err != nil {
		return err
	}
	state.k8sContainerName, err = f.k8sContainerName.String(data, 64)
	if err != nil {
		return err
	}
	state.k8sPodLabels, err = f.k8sPodLabels.String(data, 1024)
	if err != nil {
		return err
	}

	return nil
}

// setFromState writes to the corresponding data fields from the information previously saved into the statsEntry
func (f *enrichedFields) setFromState(data api.Data, state *statsEntry) error {
	if f == nil {
		return nil
	}
	if err := f.k8sNode.SetString(data, state.k8sNode); err != nil {
		return err
	}
	if err := f.k8sNamespace.SetString(data, state.k8sNamespace); err != nil {
		return err
	}
	if err := f.k8sPodName.SetString(data, state.k8sPodName); err != nil {
		return err
	}
	if err := f.k8sContainerName.SetString(data, state.k8sContainerName); err != nil {
		return err
	}
	if err := f.k8sPodLabels.SetString(data, state.k8sPodLabels); err != nil {
		return err
	}
	return nil
}

type exportedFields struct {
	// mimic original fields
	pid  uint32FieldWriter
	comm stringFieldWriter
	src  stringFieldWriter
	dst  stringFieldWriter
	// calculated fields
	sentRate    stringFieldWriter
	recvRate    stringFieldWriter
	total       stringFieldWriter
	proj24      stringFieldWriter
	proj24Bytes uint64FieldWriter
}

func populateMath(data api.Data, exported exportedFields, state *statsEntry) error {
	duration := now.Sub(state.FirstSeen)
	totalBytes := float64(state.SentRaw + state.RecvRaw)

	var sentRateBytes, recvRateBytes float64
	if duration > 10*time.Millisecond {
		sentRateBytes = float64(state.SentRaw) / duration.Seconds()
		recvRateBytes = float64(state.RecvRaw) / duration.Seconds()
	} else {
		sentRateBytes = float64(state.SentRaw)
		recvRateBytes = float64(state.RecvRaw)
	}

	totalRateBytes := sentRateBytes + recvRateBytes
	proj24Bytes := totalRateBytes * secondsPerDay

	if err := exported.sentRate.SetString(data, formatBytes(sentRateBytes)+"/s"); err != nil {
		return err
	}
	if err := exported.recvRate.SetString(data, formatBytes(recvRateBytes)+"/s"); err != nil {
		return err
	}
	if err := exported.total.SetString(data, formatBytes(totalBytes)); err != nil {
		return err
	}
	if err := exported.proj24.SetString(data, formatBytes(proj24Bytes)); err != nil {
		return err
	}
	if err := exported.proj24Bytes.SetUint64(data, uint64(proj24Bytes)); err != nil {
		return err
	}
	return nil
}

func populateExportedFields(data api.Data, exported exportedFields, enriched *enrichedFields, state *statsEntry) error {
	if err := exported.pid.SetUint32(data, state.Pid); err != nil {
		return err
	}
	if err := exported.comm.SetString(data, state.Comm); err != nil {
		return err
	}
	if err := exported.src.SetString(data, state.Src); err != nil {
		return err
	}
	if err := exported.dst.SetString(data, state.Dst); err != nil {
		return err
	}
	if err := enriched.setFromState(data, state); err != nil {
		return err
	}
	return populateMath(data, exported, state)
}

//go:wasmexport gadgetInit
func gadgetInit() (res int32) {
	defer func() {
		if err := recover(); err != nil {
			if _, ok := err.(setupError); !ok {
				panic(err)
			}
			api.Warn(err)
			res = -1
		}
	}()

	ds, err := api.GetDataSource("tcp")
	if err != nil {
		api.Warn(err.Error())
		return -1
	}

	sourceFields := getSourceFields(ds)
	exportedFields := getExportedFields(ds)
	var enrichedFields *enrichedFields

	statsMap := make(map[string]*statsEntry)

	// SubscribeArray is executed on every fetch interval, and contains all entries gathered by the "GADGET_MAPITER"
	// This module aims to provide a "dashboard" of top network connections over time.
	// However, the kernel-space BPF program can only retain limited information, so every dataArray will only contain entries for a short interval period.
	// We need to differentiate different entries/rows by a unique ID (PID/program name + src and dest IPs):
	// 1. For entries present on the data array, we'll increment counters and calculate the necessary stats.
	// 2. Previous entries not included in the data array will be recovered from historical data, updated and emitted as well.
	// This way, the resulting table will include accurate up-to-date information of all process, despite they don't constantly produce activity.
	const priority = filterOperatorPriority - 1
	if err := ds.SubscribeArray(func(source api.DataSource, dataArray api.DataArray) error {
		if enrichedFields == nil {
			enrichedFields = getEnrichedFields(ds)
		}
		emitted := make(map[string]struct{})

		// 1. Process active connections
		for i := range dataArray.Len() {
			data := dataArray.Get(i)

			// Retrieve base fields from data entry, needed for building the unique identifier
			entry, err := sourceFields.newEntryFrom(data)
			if err != nil {
				api.Warn(err)
				continue
			}
			entryID := entry.id()

			// Load previous entry, if present. otherwise complete the data from this entry and store it
			if s, ok := statsMap[entryID]; ok {
				entry = s
			} else {
				if err := enrichedFields.saveEnrichedData(data, entry); err != nil {
					api.Warn(err)
					continue
				}
				statsMap[entryID] = entry
			}

			// Observe stats
			if err := sourceFields.increaseCounters(data, entry); err != nil {
				api.Warn(err)
				continue
			}

			// Finally emit fields by calculating all stats
			if err := populateExportedFields(data, exportedFields, enrichedFields, entry); err != nil {
				api.Warn(err)
				continue
			}

			// Mark this entry as already emitted
			emitted[entryID] = struct{}{}
		}

		// 2. Append idle connections that weren't in this interval's kernel flush
		for key, state := range statsMap {
			if _, ok := emitted[key]; !ok {
				// Produce synthetic data entry from historical data not present in the current sample set
				newData := dataArray.New()
				if newData == 0 {
					api.Warn("failed to allocate new data entry")
					break
				}

				if err := populateExportedFields(newData, exportedFields, enrichedFields, state); err != nil {
					api.Warn(err)
					continue
				}

				if err := dataArray.Append(newData); err != nil {
					api.Warn(err)
					continue
				}
			}
		}

		return nil
	}, priority); err != nil {
		api.Warn(err)
		return -1
	}

	if err := configureFooter(ds); err != nil {
		// not critical, we can continue
		api.Warn(err)
	}

	return 0
}

// configureFooter registers a callback that is executed for every data array on the main datasource, but the CLI operator printed the output.
// This allows adding a footer with custom data, in this case, the elapsed time
func configureFooter(ds api.DataSource) error {
	ods, err := api.NewDataSource("output", api.DataSourceTypeSingle)
	if err != nil {
		return fmt.Errorf("creating output datasource field: %w", err)
	}
	outputField, err := ods.AddField("_text", api.Kind_String)
	if err != nil {
		return fmt.Errorf("adding text field: %w", err)
	}

	// Subscribe to the main datasource, with priority higher than the CLI operator.
	// This allows printing after all the output has already been written
	const priority = cliOperatorPriority + 1
	return ds.SubscribeArray(func(source api.DataSource, dataArray api.DataArray) error {
		if startTime.IsZero() {
			return nil
		}

		// Docs: https://inspektor-gadget.io/docs/latest/gadget-devel/output
		nd, err := ods.NewPacketSingle()
		if err != nil {
			return err
		}
		elapsed := now.Sub(startTime).Round(time.Second)
		if err := outputField.SetString(api.Data(nd), fmt.Sprintf("--- Elapsed: %s ---", elapsed)); err != nil {
			return err
		}
		return ods.EmitAndRelease(api.Packet(nd))
	}, priority)
}

/* utils.go */

func normalizeTs(ns uint64) time.Time {
	var ts time.Time
	return ts.Add(time.Duration(ns) * time.Nanosecond)
}

// The WASM clock cannot be trusted, we need to take it from the highest value observed from samples
// Every sample's "_ts" (obtained from bpf_ktime_get_boot_ns()) contains nanoseconds elapsed since system boot
// We don't need absolute time, just all our values to use the same base/epoch
var (
	startTime time.Time
	now       time.Time
)

func getSampleTimestamp(data api.Data, src sourceFields) (time.Time, error) {
	tsNs, err := src.ts.Uint64(data)
	if err != nil {
		return time.Time{}, err
	}

	ts := normalizeTs(tsNs)

	// Update artificial clock, if needed
	if ts.After(now) {
		now = ts
	}
	// Record oldest timestamp observed
	if startTime.IsZero() || ts.Before(startTime) {
		startTime = ts
	}
	return ts, nil
}

var ipParserBuffer = make([]byte, 32)

func getIPFromField(data api.Data, ipField bytesField) (string, error) {
	if n, err := ipField.Bytes(data, ipParserBuffer[:cap(ipParserBuffer)]); err != nil {
		return "", err
	} else {
		return parseIPBytesStruct(ipParserBuffer[:n]), nil
	}
}

// parseIPBytesStruct safely parses the C struct memory, ignoring all padding and union garbage
// https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.50.1/include/gadget/types.h#L13-L24
func parseIPBytesStruct(raw []byte) string {
	// gadget_ip_addr_t union (16 bytes) + (1 byte) for version
	if len(raw) < 17 {
		return fmt.Sprintf("invalid-len-%x", raw)
	}
	switch version := raw[16]; version {
	case 4:
		return net.IP(raw[0:4]).String()
	case 6:
		return net.IP(raw[0:16]).String()
	default:
		return fmt.Sprintf("unknown-v%d-%x", version, raw)
	}
}

var units = []string{"B", "KB", "MB", "GB", "TB", "PB"}

func formatBytes(size float64) string {
	for _, unit := range units[:len(units)-1] {
		if size < 1024 {
			return fmt.Sprintf("%.1f %s", size, unit)
		}
		size /= 1024
	}
	return fmt.Sprintf("%.1f %s", size, units[len(units)-1])
}

func main() {}

/* fields.go: interfaces implementing a subset of api.Field methods */

type stringField interface {
	String(api.Data, uint32) (string, error)
}

type stringFieldWriter interface {
	stringField
	SetString(api.Data, string) error
}

type bytesField interface {
	Bytes(api.Data, []byte) (uint32, error)
}

type uint64Field interface {
	Uint64(api.Data) (uint64, error)
}

type uint64FieldWriter interface {
	uint64Field
	SetUint64(api.Data, uint64) error
}

type uint32Field interface {
	Uint32(api.Data) (uint32, error)
}

type uint32FieldWriter interface {
	uint32Field
	SetUint32(api.Data, uint32) error
}

type setupError error

func mustGetField(ds api.DataSource, name string) api.Field {
	field, err := ds.GetField(name)
	if err != nil {
		panic(setupError(err))
	}
	return field
}

func mustAddField(ds api.DataSource, name string, kind api.FieldKind) api.Field {
	field, err := ds.AddField(name, kind)
	if err != nil {
		panic(setupError(err))
	}
	return field
}
