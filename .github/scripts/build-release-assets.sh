#!/usr/bin/env bash
set -euo pipefail

release_tag="${1:?Usage: build-release-assets.sh <release-tag> <rid>}"
rid="${2:?Usage: build-release-assets.sh <release-tag> <rid>}"
project="src/Transiever.ManageSieve.Cli/Transiever.ManageSieve.Cli.csproj"
binary="msieve"
artifacts="artifacts"
publish_root="$artifacts/publish"

if [[ "$release_tag" != v* ]]; then
  echo "Release tag must start with v: $release_tag" >&2
  exit 2
fi

case "$rid" in
  win-x64|win-x86|linux-x64) ;;
  *)
    echo "Unsupported runtime identifier: $rid" >&2
    exit 2
    ;;
esac

version="${release_tag#v}"
output="$publish_root/$rid"
mkdir -p "$artifacts" "$output"

dotnet publish "$project" --configuration Release --runtime "$rid" --self-contained true \
  -p:PublishAot=true -p:PublishTrimmed=true -p:PublishSingleFile=true \
  -p:InvariantGlobalization=false -p:TreatWarningsAsErrors=true -p:Version="$version" \
  --output "$output"

if [[ "$rid" == win-* ]]; then
  executable="$output/$binary.exe"
  archive="$artifacts/$binary-$release_tag-$rid.zip"
else
  executable="$output/$binary"
  archive="$artifacts/$binary-$release_tag-$rid.tar.gz"
fi

test -f "$executable"
format="$(file -b "$executable")"
case "$rid" in
  win-x64) [[ "$format" == PE32+\ executable* && "$format" == *x86-64* ]] ;;
  win-x86) [[ "$format" == PE32\ executable* && ( "$format" == *80386* || "$format" == *i386* ) ]] ;;
  linux-x64) [[ "$format" == ELF\ 64-bit* && "$format" == *x86-64* ]] ;;
esac || {
  echo "Unexpected executable format for $rid: $format" >&2
  exit 1
}

if [[ "$rid" == win-* ]]; then
  pwsh -NoLogo -NoProfile -Command \
    "Compress-Archive -LiteralPath '$executable' -DestinationPath '$archive' -Force"
  archive_entries="$(unzip -Z1 "$archive")"
else
  tar -czf "$archive" -C "$output" "$binary"
  archive_entries="$(tar -tzf "$archive")"
fi

test -f "$archive"
[[ "$archive_entries" == "$(basename "$executable")" ]] || {
  echo "Archive must contain only $(basename "$executable"): $archive_entries" >&2
  exit 1
}
