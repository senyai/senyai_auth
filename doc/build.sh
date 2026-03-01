#!/usr/bin/env bash
fossil pikchr -dark overview.pikchr > overview_dark.svg && \
echo "saved overview_dark.svg"
fossil pikchr overview.pikchr > overview_light.svg && \
echo "overview_light.svg"
