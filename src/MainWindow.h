#pragma once

#include <QCheckBox>
#include <QDateTime>
#include <QLabel>
#include <QListWidget>
#include <QMainWindow>
#include <QIODevice>
#include <QPushButton>
#include <QTableWidget>
#include <QVector>

#include <QtCharts/QChartView>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void loadData();
    void plotSelected();
    void savePlot();

private:
    struct TableData {
        QStringList headers;
        QVector<QStringList> rows;
        int timestampIndex = -1;
    };

    QString locateFile(const QString &filename) const;
    bool loadCredentials(QString *host, QString *user, QString *pass, QString *error) const;
    bool downloadFtpFile(const QString &host,
                         const QString &user,
                         const QString &pass,
                         QByteArray *out,
                         QString *error) const;
    bool loadCsvFromDevice(QIODevice *device, TableData *out, QString *error) const;
    QStringList parseCsvLine(const QString &line) const;
    QDateTime parseTimestamp(const QString &text) const;
    void populateVariables();
    void populatePreview();
    void resetChart();

    QCheckBox *useFtpCheck_ = nullptr;
    QLabel *statusLabel_ = nullptr;
    QListWidget *varList_ = nullptr;
    QTableWidget *previewTable_ = nullptr;
    QPushButton *reloadButton_ = nullptr;
    QPushButton *plotButton_ = nullptr;
    QPushButton *saveButton_ = nullptr;
    QPushButton *quitButton_ = nullptr;
    QChartView *chartView_ = nullptr;

    TableData data_;
};
