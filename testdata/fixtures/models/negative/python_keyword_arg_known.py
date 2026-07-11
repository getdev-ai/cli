# canonical Anthropic SDK call shape (A12, 03-REVIEW.md) — `model=` as a
# keyword argument, not a top-level assignment — a known family here must
# never fire
client.messages.create(model="claude-fable-5")
