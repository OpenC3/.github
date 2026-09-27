# The disposable container each AI review turn runs in (see ai_review_loop.sh), and the API proxy
# that holds the turn's key (api_proxy.py). The base image is pinned by digest, because a tag can
# be moved to point at a different image.
# node:24-bookworm (includes git and python3, which the agents and the proxy need)
FROM node:24-bookworm@sha256:64af3819f9275802414d7cdc38c27e9d82bd564dec4d4da87d008255d36c63b4

RUN npm install -g @anthropic-ai/claude-code@2.1.283 @openai/codex@0.157.1 \
  && npm cache clean --force

COPY api_proxy.py /opt/ai-review/api_proxy.py
