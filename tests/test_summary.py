from twoparty.bench import baseline, summarize


def test_summarize():
    s = summarize([1.0, 2.0, 3.0, 4.0, 100.0])
    assert s["n"] == 5 and s["median_ms"] == 3.0 and s["max_ms"] == 100.0


def test_baseline_runs():
    out = baseline(5)
    assert len(out) == 5 and all(x > 0 for x in out)
