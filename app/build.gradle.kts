import java.time.ZonedDateTime
import java.util.Properties
import java.time.format.DateTimeFormatter

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

/*
 * Release signing: keystore.properties in the project root (not in git), with
 * storeFile, storePassword, keyAlias and keyPassword. Without it the release
 * build is left unsigned (for F-Droid and others who sign it themselves).
 */
val keystoreProps = rootProject.file("keystore.properties").takeIf { it.isFile }?.let { f ->
    Properties().apply { f.inputStream().use { load(it) } }
}

android {
    namespace = "nl.sc00by.networkscanner"
    compileSdk = 37

    defaultConfig {
        applicationId = "nl.sc00by.networkscanner"
        minSdk = 29
        targetSdk = 37
        // Release numbering: versionName goes up by 0.001 per release (0.9 -> 0.901 -> 0.902 …);
        // versionCode always +1.
        versionCode = 21
        versionName = "0.912"
    }

    signingConfigs {
        if (keystoreProps != null) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // R8: shrinks the app from ~30 MB (debug) to a few MB.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.kotlinx.coroutines.android)
    debugImplementation(libs.compose.ui.tooling)
    testImplementation(libs.junit)
}

/** Copies NetworkScanner.txt (project root) into the app's assets; shown behind the "Info" button. */
abstract class CopyInfoText : DefaultTask() {
    @get:InputFile
    abstract val source: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        val out = outputDir.get().asFile
        out.mkdirs()
        source.get().asFile.copyTo(File(out, "NetworkScanner.txt"), overwrite = true)
        // Build date/time shown on the Info card.
        val now = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))
        File(out, "buildtime.txt").writeText(now)
    }
}

val copyInfoText = tasks.register<CopyInfoText>("copyInfoText") {
    source.set(rootProject.layout.projectDirectory.file("NetworkScanner.txt"))
    outputs.upToDateWhen { false } // new build time on every build
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(copyInfoText, CopyInfoText::outputDir)
    }
}
