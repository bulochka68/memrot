import json

from memrot.tracer import JSONLTracer


def test_tracer_writes_one_json_object_per_line(tmp_path):
    path = str(tmp_path / "trace.jsonl")
    tracer = JSONLTracer(path=path)
    tracer.log(run_id="run1", trace_id="variant-a", phase="baseline", direction="request", text="hello")
    tracer.log(run_id="run1", trace_id="variant-a", phase="baseline", direction="response", text="world",
              canary="C-1", canary_present=False)
    tracer.close()

    lines = open(path, encoding="utf-8").read().splitlines()
    assert len(lines) == 2
    objs = [json.loads(l) for l in lines]
    assert all("event_id" in o and "run_id" in o and "trace_id" in o for o in objs)
    assert objs[1]["canary_present"] is False


def test_tracer_computes_digest_and_bounded_fragment_not_raw_text():
    tracer = JSONLTracer()
    long_text = "x" * 1000
    event = tracer.log(run_id="run1", trace_id="v", text=long_text)
    assert event.text_digest.startswith("sha256:")
    assert len(event.text_fragment) < len(long_text)


def test_tracer_without_path_still_records_in_memory():
    tracer = JSONLTracer()
    tracer.log(run_id="run1", trace_id="v", phase="probe")
    assert len(tracer.events) == 1
    tracer.close()   # must not raise when there is no file handle
