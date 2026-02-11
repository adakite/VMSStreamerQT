#pragma once

#include <QCheckBox>
#include <QDateTime>
#include <QLabel>
#include <QListWidget>
#include <QLineEdit>
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
    void loadData(bool quiet = false);
    void plotSelected();
    void savePlot();
    void chooseSaveDir();
    void chooseLocalFile();

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
    QString defaultSaveDir() const;
    QString defaultLocalFile() const;
    void updateSaveControls();
    void updateSourceControls();
    void populateVariables();
    void populatePreview();
    void resetChart();

    QCheckBox *useFtpCheck_ = nullptr;
    QCheckBox *saveFtpCheck_ = nullptr;
    QLineEdit *saveDirEdit_ = nullptr;
    QPushButton *browseSaveDirButton_ = nullptr;
    QLineEdit *localFileEdit_ = nullptr;
    QPushButton *browseLocalFileButton_ = nullptr;
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
