package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOutputRingNoEviction(t *testing.T) {
	r := newOutputRing(64)
	r.append([]byte("hello"))
	if r.totalOff != 5 || r.headOff != 0 {
		t.Fatalf("offsets: head=%d total=%d", r.headOff, r.totalOff)
	}
	tail, gap := r.tailFrom(0)
	if gap || string(tail) != "hello" {
		t.Fatalf("tailFrom(0)=%q gap=%v", tail, gap)
	}
	tail, gap = r.tailFrom(3)
	if gap || string(tail) != "lo" {
		t.Fatalf("tailFrom(3)=%q gap=%v", tail, gap)
	}
	if tail, gap := r.tailFrom(5); gap || tail != nil {
		t.Fatalf("tailFrom(5)=%q gap=%v (want nil,false)", tail, gap)
	}
}

func TestOutputRingEviction(t *testing.T) {
	r := newOutputRing(4)
	r.append([]byte("abcdef")) // keeps last 4: "cdef"
	if string(r.buf) != "cdef" || r.headOff != 2 || r.totalOff != 6 {
		t.Fatalf("buf=%q head=%d total=%d", r.buf, r.headOff, r.totalOff)
	}
	// An offset before the retained head is a gap; we get whatever survived.
	tail, gap := r.tailFrom(0)
	if !gap || string(tail) != "cdef" {
		t.Fatalf("tailFrom(0)=%q gap=%v (want cdef,true)", tail, gap)
	}
	// An offset at/after head replays exactly, no gap.
	tail, gap = r.tailFrom(4)
	if gap || string(tail) != "ef" {
		t.Fatalf("tailFrom(4)=%q gap=%v (want ef,false)", tail, gap)
	}
}

func TestStreamSinkResumeForwardsAfterReplay(t *testing.T) {
	s := newStreamSink()
	// Output produced before any browser is live: recorded to the ring only.
	_, _ = s.Write([]byte("AB"))
	var w bytes.Buffer
	// First (fresh) attach: browser rendered 0 bytes, so the full ring replays.
	if !s.resumeOnce(&w, 0) {
		t.Fatal("resumeOnce should report a resume on first attach")
	}
	// Now live: subsequent output forwards immediately and in order.
	_, _ = s.Write([]byte("CD"))
	if w.String() != "ABCD" {
		t.Fatalf("got %q want ABCD", w.String())
	}
	// Re-resuming the same conn is a no-op (idempotent).
	if s.resumeOnce(&w, 0) {
		t.Fatal("resumeOnce on the same conn should report false")
	}
}

func TestStreamSinkReattachReplaysOnlyMissingTail(t *testing.T) {
	s := newStreamSink()
	_, _ = s.Write([]byte("ABCDE")) // 5 bytes produced; browser rendered "ABC" (offset 3)
	var w bytes.Buffer
	if !s.resumeOnce(&w, 3) {
		t.Fatal("resumeOnce should report a resume")
	}
	// Only the missing tail "DE" is replayed — no double-render of "ABC".
	if w.String() != "DE" {
		t.Fatalf("got %q want DE (only the missing tail)", w.String())
	}
}

func TestStreamSinkReattachGapNotice(t *testing.T) {
	s := streamSink{ring: newOutputRing(8)}
	_, _ = s.Write([]byte("0123456789")) // ring retains last 8: "23456789"
	var w bytes.Buffer
	// Browser rendered only "01" (offset 2) but that output was evicted.
	if !s.resumeOnce(&w, 0) {
		t.Fatal("resumeOnce should report a resume")
	}
	out := w.String()
	if !strings.Contains(out, "reconnected") {
		t.Fatalf("expected a gap notice, got %q", out)
	}
	if !strings.HasSuffix(out, "23456789") {
		t.Fatalf("expected surviving tail at end, got %q", out)
	}
}

func TestStreamSinkDetachStopsForwarding(t *testing.T) {
	s := newStreamSink()
	var w bytes.Buffer
	s.resumeOnce(&w, 0)
	_, _ = s.Write([]byte("live"))
	s.detach(&w)
	_, _ = s.Write([]byte("after-detach"))
	if w.String() != "live" {
		t.Fatalf("got %q want only %q (no forwarding after detach)", w.String(), "live")
	}
}
