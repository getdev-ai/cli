# canonical Anthropic/OpenAI SDK call shape (A12, 03-REVIEW.md) — a
# `keyword_argument` was previously invisible to the string-literal
# extraction query, so this hallucinated model id went undetected
client.messages.create(model="totally-fake-model-3")
