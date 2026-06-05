# Android Publishing Guide

This Gradle project packages Token Core native libraries into an Android AAR and
publishes `io.github.consenlabs.android:token-core` to Maven Central with
JReleaser.

For the repository-wide release policy, see [`../../doc/RELEASE.md`](../../doc/RELEASE.md).

## Prerequisites

Local Android packaging requires:

- Java 17
- Android SDK
- Android NDK `25.2.9519653` for release-equivalent native builds
- Gradle wrapper from this directory
- Rust Android targets documented in [`../../doc/BUILD.md`](../../doc/BUILD.md)
- Protobuf

Release publishing requires GitHub environment secrets:

- `SIGNING_SECRET_JRELEASER`
- `GPG_PUBLIC_KEY`
- `GPG_PRIVATE_KEY`
- `MAVENCENTRAL_USERNAME`
- `MAVENCENTRAL_PASSWORD`
- `SLACK_WEBHOOK` for release notifications

The workflow maps these secrets to the `JRELEASER_*` environment variables used
by JReleaser.

## Local Build Check

Build the AAR from this directory:

```bash
./gradlew assemble
```

Validate the generated JReleaser configuration:

```bash
./gradlew jreleaserConfig
```

The generated trace and output files are written under `build/jreleaser/`.

## Versioning

The release workflow reads the repository root [`../../VERSION`](../../VERSION)
and appends the release commit short SHA when publishing. For example, root
version `2.8.4` from commit `abc1234` becomes `2.8.4+abc1234` in the workflow.

For local publishing checks, pass the version explicitly when needed:

```bash
VERSION=2.8.4-local ./gradlew publishProductionPublicationToStagingRepository
```

## Automated Release Flow

The GitHub Actions workflow
[`../../.github/workflows/build-release-android.yml`](../../.github/workflows/build-release-android.yml)
runs after an approved pull request review. It:

1. Checks out the reviewed PR head commit.
2. Installs Rust, Android SDK/NDK, Java, Gradle, and Protobuf.
3. Builds native libraries with [`../../script/build-android.sh`](../../script/build-android.sh).
4. Builds `tokencore-release.aar`.
5. Publishes to a local staging repository.
6. Deploys to Maven Central with JReleaser.
7. Uploads JReleaser logs as workflow artifacts.

## Consuming the AAR

```kotlin
dependencies {
    implementation("io.github.consenlabs.android:token-core:<version>")
}
```

Use the exact version published by the release workflow.

## Troubleshooting

- Check `build/jreleaser/trace.log` for detailed JReleaser errors.
- Check `build/jreleaser/output.properties` for generated deployment metadata.
- Confirm that the AAR exists at
  `tokencore/build/outputs/aar/tokencore-release.aar` before publishing.
- Confirm that all required secrets are available in the `release` GitHub
  environment.
