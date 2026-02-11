#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QPainter>
#include <QPixmap>
#include <QSplashScreen>
#include <QString>

#include <curl/curl.h>

#include "MainWindow.h"

namespace {
QString locateSplashIcon() {
    const QString baseDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        QDir(baseDir).filePath("vmsstreamer.icns"),
        QDir(baseDir).filePath(QStringLiteral("../Resources/vmsstreamer.icns")),
        QDir(baseDir).filePath(QStringLiteral("../../vmsstreamer.icns")),
        QDir(baseDir).filePath(QStringLiteral("../../../vmsstreamer.icns")),
    };

    for (const QString &candidate : candidates) {
        QFileInfo info(candidate);
        if (info.exists() && info.isFile()) {
            return info.absoluteFilePath();
        }
    }
    return {};
}

QPixmap buildSplash() {
    const QSize size(640, 360);
    QPixmap pixmap(size);
    pixmap.fill(QColor("#1f2226"));

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    QPixmap icon;
    const QString iconPath = locateSplashIcon();
    if (!iconPath.isEmpty()) {
        icon.load(iconPath);
    }

    const int iconSize = 96;
    const int marginTop = 70;
    if (!icon.isNull()) {
        QPixmap scaled = icon.scaled(iconSize, iconSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        const int x = (size.width() - scaled.width()) / 2;
        painter.drawPixmap(x, marginTop, scaled);
    } else {
        painter.setBrush(QColor("#3a4046"));
        painter.setPen(Qt::NoPen);
        const QRect circle((size.width() - iconSize) / 2, marginTop, iconSize, iconSize);
        painter.drawEllipse(circle);
    }

    QFont titleFont("Helvetica Neue", 22, QFont::DemiBold);
    painter.setFont(titleFont);
    painter.setPen(QColor("#f5f5f5"));
    painter.drawText(QRect(0, marginTop + iconSize + 16, size.width(), 32),
                     Qt::AlignHCenter, "VMS Streamer");

    QFont subFont("Helvetica Neue", 12);
    painter.setFont(subFont);
    painter.setPen(QColor("#9aa3aa"));
    painter.drawText(QRect(0, marginTop + iconSize + 52, size.width(), 22),
                     Qt::AlignHCenter, "Loading data...");

    painter.end();
    return pixmap;
}
}  // namespace

int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    QApplication app(argc, argv);

    QSplashScreen splash(buildSplash());
    splash.setWindowFlag(Qt::WindowStaysOnTopHint);
    splash.show();
    app.processEvents();

    MainWindow window;
    window.show();

    splash.finish(&window);

    int exitCode = app.exec();
    curl_global_cleanup();
    return exitCode;
}
