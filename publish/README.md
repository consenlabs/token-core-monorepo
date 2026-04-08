## Publish

### NPM (`@consenlabs/tcx-wasm`)

```bash
# Build the optimized WASM package into publish/npm/
make build-npm

# Publish to npmjs.com (requires npm login with @consenlabs org access)
make publish-npm

# Or manually:
cd publish/npm && npm publish
```

### Android
```bash
# copy all so to ./publish/android/tokencore/src/jniLabs
$ ./gradlew assemble
$ ./gradlew pPPTNR #publishProductionPublicationToNexusRepository
```