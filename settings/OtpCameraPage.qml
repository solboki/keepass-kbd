// Scan du QR code de double authentification avec l'appareil photo (QR affiché sur un
// ordinateur). Une photo est prise toutes les secondes environ dans le dossier d'exécution
// de la session, lue par le service, qui l'efface aussitôt.
import QtQuick 2.0
import QtMultimedia 5.6
import Sailfish.Silica 1.0
import "KpxStrings.js" as S

Page {
    id: cam
    property var daemon: null      // DBusInterface du service, fourni par la page appelante
    property var target: null      // page d'ajout : target.useScanned(uri)
    property string scanPath: ""
    property string status: ""
    property bool reading: false
    property bool done: false

    readonly property string lang: S.lang(Qt.locale().name)
    function t(key, arg) { return S.tr(lang, key, arg) }

    allowedOrientations: Orientation.Portrait

    function shoot() {
        if (done || reading || scanPath === "" || camera.cameraStatus !== Camera.ActiveStatus) return
        camera.imageCapture.captureToLocation(scanPath)
    }

    Component.onCompleted: daemon.typedCall("OtpScanPath", [], function(p) { cam.scanPath = String(p || "") },
                                            function() { cam.status = cam.t("service unavailable") })

    Camera {
        id: camera
        captureMode: Camera.CaptureStillImage
        focus.focusMode: Camera.FocusContinuous
        focus.focusPointMode: Camera.FocusPointCenter
        imageCapture.resolution: Qt.size(1600, 1200)
        onCameraStatusChanged: if (cameraStatus === Camera.ActiveStatus) shootTimer.restart()
        onErrorChanged: if (error !== Camera.NoError) cam.status = cam.t("Camera unavailable") + " (" + errorString + ")"
        imageCapture.onImageSaved: {
            cam.reading = true
            cam.daemon.typedCall("OtpFromImage", [{ "type": "s", "value": path }], function(json) {
                cam.reading = false
                var r = {}
                try { r = JSON.parse(json) } catch (e) {}
                if (r.ok) {
                    cam.done = true
                    camera.stop()
                    cam.target.useScanned(r.uri)
                    pageStack.pop()
                } else {
                    // Pas encore de QR code lisible : on recommence.
                    cam.status = r.error || ""
                    shootTimer.restart()
                }
            }, function() { cam.reading = false; cam.status = cam.t("service unavailable") })
        }
        imageCapture.onCaptureFailed: { cam.status = message; shootTimer.restart() }
    }

    Timer {
        id: shootTimer
        interval: 900
        onTriggered: cam.shoot()
    }

    onStatusChanged: {
        if (status === PageStatus.Deactivating || status === PageStatus.Inactive) {
            shootTimer.stop()
            camera.stop()
        } else if (status === PageStatus.Active && !done) {
            camera.start()
        }
    }

    VideoOutput {
        anchors.fill: parent
        source: camera
        autoOrientation: true
        fillMode: VideoOutput.PreserveAspectCrop
    }

    // Cadre de visée
    Rectangle {
        anchors.centerIn: parent
        width: Math.min(parent.width, parent.height) * 0.7
        height: width
        color: "transparent"
        radius: Theme.paddingLarge
        border.width: Theme.paddingSmall / 2
        border.color: Theme.highlightColor
    }

    Rectangle {
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        height: hint.height + 2 * Theme.paddingLarge
        color: Theme.rgba("black", 0.6)
        Label {
            id: hint
            anchors { left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter
                      leftMargin: Theme.horizontalPageMargin; rightMargin: Theme.horizontalPageMargin }
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: "white"
            text: cam.t("Point the camera at the QR code") + (cam.status !== "" ? "\n" + cam.status : "")
        }
    }
}
