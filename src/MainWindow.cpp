#include "MainWindow.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QMargins>
#include <QPainter>
#include <QPageSize>
#include <QPdfWriter>
#include <QSaveFile>
#include <QSet>
#include <QSplitter>
#include <QStandardPaths>
#include <QTextStream>
#include <QVBoxLayout>

#include <QtCharts/QAbstractSeries>
#include <QtCharts/QChart>
#include <QtCharts/QDateTimeAxis>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>

#include <algorithm>
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace {
constexpr const char *kDataFileName = "Quaraze.csv";
constexpr const char *kTimestampColumn = "TIMESTAMP";
constexpr const char *kRecordColumn = "RECORD";
constexpr int kPreviewRowCount = 100;

size_t writeToBuffer(void *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *buffer = static_cast<QByteArray *>(userdata);
    const qsizetype bytes = static_cast<qsizetype>(size * nmemb);
    buffer->append(static_cast<char *>(ptr), bytes);
    return static_cast<size_t>(bytes);
}

bool base64UrlDecode(const QByteArray &input, QByteArray *output, QString *error) {
    if (!output) {
        return false;
    }

    QByteArray normalized = input;
    normalized.replace('-', '+');
    normalized.replace('_', '/');

    const int mod = normalized.size() % 4;
    if (mod == 1) {
        if (error) {
            *error = "Invalid base64 length.";
        }
        return false;
    }
    if (mod == 2) {
        normalized.append("==");
    } else if (mod == 3) {
        normalized.append('=');
    }

    QByteArray decoded((normalized.size() / 4) * 3, Qt::Uninitialized);
    const int len = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(decoded.data()),
                                    reinterpret_cast<const unsigned char *>(normalized.constData()),
                                    normalized.size());
    if (len < 0) {
        if (error) {
            *error = "Base64 decode failed.";
        }
        return false;
    }

    int padding = 0;
    if (normalized.endsWith("==")) {
        padding = 2;
    } else if (normalized.endsWith("=")) {
        padding = 1;
    }
    decoded.truncate(len - padding);
    *output = decoded;
    return true;
}

bool fernetDecrypt(const QByteArray &tokenB64,
                   const QByteArray &keyB64,
                   QByteArray *plaintext,
                   QString *error) {
    QByteArray key;
    if (!base64UrlDecode(keyB64.trimmed(), &key, error)) {
        if (error && error->isEmpty()) {
            *error = "Invalid key encoding.";
        }
        return false;
    }
    if (key.size() != 32) {
        if (error) {
            *error = "Invalid Fernet key length.";
        }
        return false;
    }

    QByteArray token;
    if (!base64UrlDecode(tokenB64.trimmed(), &token, error)) {
        if (error && error->isEmpty()) {
            *error = "Invalid token encoding.";
        }
        return false;
    }
    if (token.size() < 1 + 8 + 16 + 32) {
        if (error) {
            *error = "Token too short.";
        }
        return false;
    }

    const unsigned char version = static_cast<unsigned char>(token.at(0));
    if (version != 0x80) {
        if (error) {
            *error = "Unsupported token version.";
        }
        return false;
    }

    const QByteArray signingKey = key.left(16);
    const QByteArray encryptionKey = key.mid(16, 16);

    const QByteArray signedData = token.left(token.size() - 32);
    const QByteArray signature = token.right(32);

    unsigned int hmacLen = 0;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    if (!HMAC(EVP_sha256(),
              signingKey.constData(),
              signingKey.size(),
              reinterpret_cast<const unsigned char *>(signedData.constData()),
              signedData.size(),
              hmac,
              &hmacLen)) {
        if (error) {
            *error = "HMAC calculation failed.";
        }
        return false;
    }
    if (hmacLen != 32 || CRYPTO_memcmp(hmac, signature.constData(), 32) != 0) {
        if (error) {
            *error = "Invalid token signature.";
        }
        return false;
    }

    const int ivOffset = 1 + 8;
    const QByteArray iv = token.mid(ivOffset, 16);
    const QByteArray cipherText = token.mid(ivOffset + 16, token.size() - ivOffset - 16 - 32);
    if (cipherText.isEmpty()) {
        if (error) {
            *error = "Token payload missing.";
        }
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (error) {
            *error = "Failed to init cipher context.";
        }
        return false;
    }

    QByteArray out(cipherText.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()), 0);
    int outLen1 = 0;
    int outLen2 = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                                reinterpret_cast<const unsigned char *>(encryptionKey.constData()),
                                reinterpret_cast<const unsigned char *>(iv.constData())) == 1
        && EVP_DecryptUpdate(ctx,
                             reinterpret_cast<unsigned char *>(out.data()),
                             &outLen1,
                             reinterpret_cast<const unsigned char *>(cipherText.constData()),
                             cipherText.size()) == 1
        && EVP_DecryptFinal_ex(ctx,
                               reinterpret_cast<unsigned char *>(out.data()) + outLen1,
                               &outLen2) == 1;

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        if (error) {
            *error = "Token decryption failed.";
        }
        return false;
    }

    out.truncate(outLen1 + outLen2);
    if (plaintext) {
        *plaintext = out;
    }
    return true;
}

bool looksEncrypted(const QString &value) {
    return value.trimmed().startsWith("gAAAA");
}
}  // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("VMS Streamer V2");
    resize(1024, 768);

    auto *central = new QWidget(this);
    setCentralWidget(central);

    auto *mainLayout = new QVBoxLayout(central);

    auto *controlLayout = new QHBoxLayout();
    useFtpCheck_ = new QCheckBox("Use FTP data", this);
    useFtpCheck_->setChecked(false);
    reloadButton_ = new QPushButton("Reload", this);
    statusLabel_ = new QLabel("Ready", this);
    statusLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    controlLayout->addWidget(useFtpCheck_);
    controlLayout->addWidget(reloadButton_);
    controlLayout->addStretch();
    controlLayout->addWidget(statusLabel_);
    mainLayout->addLayout(controlLayout);

    auto *localLayout = new QHBoxLayout();
    auto *localLabel = new QLabel("Local file", this);
    localFileEdit_ = new QLineEdit(this);
    localFileEdit_->setPlaceholderText("Choose a CSV file...");
    localFileEdit_->setText(defaultLocalFile());
    browseLocalFileButton_ = new QPushButton("Browse…", this);

    localLayout->addWidget(localLabel);
    localLayout->addWidget(localFileEdit_, 1);
    localLayout->addWidget(browseLocalFileButton_);
    mainLayout->addLayout(localLayout);

    auto *saveLayout = new QHBoxLayout();
    saveFtpCheck_ = new QCheckBox("Save FTP data to", this);
    saveFtpCheck_->setChecked(false);
    saveDirEdit_ = new QLineEdit(this);
    saveDirEdit_->setReadOnly(true);
    saveDirEdit_->setText(defaultSaveDir());
    browseSaveDirButton_ = new QPushButton("Choose…", this);

    saveLayout->addWidget(saveFtpCheck_);
    saveLayout->addWidget(saveDirEdit_, 1);
    saveLayout->addWidget(browseSaveDirButton_);
    mainLayout->addLayout(saveLayout);

    varList_ = new QListWidget(this);
    varList_->setSelectionMode(QAbstractItemView::MultiSelection);

    previewTable_ = new QTableWidget(this);
    previewTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    previewTable_->setSelectionMode(QAbstractItemView::NoSelection);
    previewTable_->setFocusPolicy(Qt::NoFocus);
    previewTable_->setAlternatingRowColors(true);
    previewTable_->horizontalHeader()->setStretchLastSection(true);

    auto *dataSplitter = new QSplitter(Qt::Horizontal, this);
    dataSplitter->addWidget(varList_);
    dataSplitter->addWidget(previewTable_);
    dataSplitter->setStretchFactor(0, 1);
    dataSplitter->setStretchFactor(1, 3);
    mainLayout->addWidget(dataSplitter, 2);

    auto *buttonLayout = new QHBoxLayout();
    plotButton_ = new QPushButton("Plot", this);
    saveButton_ = new QPushButton("Save Plot", this);
    quitButton_ = new QPushButton("Quit", this);
    buttonLayout->addWidget(plotButton_);
    buttonLayout->addWidget(saveButton_);
    buttonLayout->addStretch();
    buttonLayout->addWidget(quitButton_);
    mainLayout->addLayout(buttonLayout);

    chartView_ = new QChartView(new QChart(), this);
    chartView_->setRenderHint(QPainter::Antialiasing);
    chartView_->setVisible(false);
    mainLayout->addWidget(chartView_, 3);

    connect(reloadButton_, &QPushButton::clicked, this, [this]() { loadData(false); });
    connect(useFtpCheck_, &QCheckBox::toggled, this, &MainWindow::updateSourceControls);
    connect(saveFtpCheck_, &QCheckBox::toggled, this, &MainWindow::updateSaveControls);
    connect(browseSaveDirButton_, &QPushButton::clicked, this, &MainWindow::chooseSaveDir);
    connect(browseLocalFileButton_, &QPushButton::clicked, this, &MainWindow::chooseLocalFile);
    connect(plotButton_, &QPushButton::clicked, this, &MainWindow::plotSelected);
    connect(saveButton_, &QPushButton::clicked, this, &MainWindow::savePlot);
    connect(quitButton_, &QPushButton::clicked, qApp, &QCoreApplication::quit);

    updateSourceControls();
    updateSaveControls();
    loadData(true);
}

QString MainWindow::locateFile(const QString &filename) const {
    const QString baseDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        QDir(baseDir).filePath(filename),
        QDir(baseDir).filePath(QStringLiteral("../Resources/") + filename),
        QDir(baseDir).filePath(QStringLiteral("../../") + filename),   // .app bundle root
        QDir(baseDir).filePath(QStringLiteral("../../../") + filename), // folder containing the .app
        QDir(QDir::currentPath()).filePath(filename),
    };

    for (const QString &candidate : candidates) {
        QFileInfo info(candidate);
        if (info.exists() && info.isFile()) {
            return info.absoluteFilePath();
        }
    }

    return {};
}

bool MainWindow::loadCredentials(QString *host, QString *user, QString *pass, QString *error) const {
    const QString credsPath = locateFile("credentials.json");
    if (credsPath.isEmpty()) {
        if (error) {
            *error = "credentials.json not found next to the app.";
        }
        return false;
    }

    QFile file(credsPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (error) {
            *error = QString("Failed to open credentials.json: %1").arg(file.errorString());
        }
        return false;
    }

    QJsonParseError jsonError{};
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &jsonError);
    if (jsonError.error != QJsonParseError::NoError || !doc.isObject()) {
        if (error) {
            *error = QString("Invalid credentials.json: %1").arg(jsonError.errorString());
        }
        return false;
    }

    const QJsonObject obj = doc.object();
    const QString hostValue = obj.value("ftp_host").toString();
    const QString userValue = obj.value("ftp_user").toString();
    const QString passValue = obj.value("ftp_pass").toString();

    if (hostValue.isEmpty() || userValue.isEmpty() || passValue.isEmpty()) {
        if (error) {
            *error = "credentials.json must include ftp_host, ftp_user, and ftp_pass.";
        }
        return false;
    }

    const bool needsKey = looksEncrypted(hostValue) || looksEncrypted(userValue) || looksEncrypted(passValue);
    QByteArray keyData;
    if (needsKey) {
        const QString keyPath = locateFile("key.key");
        if (keyPath.isEmpty()) {
            if (error) {
                *error = "Encrypted credentials detected but key.key was not found.";
            }
            return false;
        }
        QFile keyFile(keyPath);
        if (!keyFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            if (error) {
                *error = QString("Failed to open key.key: %1").arg(keyFile.errorString());
            }
            return false;
        }
        keyData = keyFile.readAll().trimmed();
        if (keyData.isEmpty()) {
            if (error) {
                *error = "key.key is empty.";
            }
            return false;
        }
    }

    auto decodeValue = [&](const QString &label, const QString &value, QString *outValue) -> bool {
        if (!outValue) {
            return true;
        }
        if (!looksEncrypted(value)) {
            *outValue = value.trimmed();
            return true;
        }
        QByteArray plaintext;
        QString decryptError;
        if (!fernetDecrypt(value.toUtf8(), keyData, &plaintext, &decryptError)) {
            if (error) {
                *error = QString("%1 decryption failed: %2").arg(label, decryptError);
            }
            return false;
        }
        *outValue = QString::fromUtf8(plaintext);
        return true;
    };

    if (!decodeValue("ftp_host", hostValue, host)) return false;
    if (!decodeValue("ftp_user", userValue, user)) return false;
    if (!decodeValue("ftp_pass", passValue, pass)) return false;
    return true;
}

QString MainWindow::defaultSaveDir() const {
    QString base = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (base.isEmpty()) {
        base = QDir::homePath();
    }
    return QDir(base).filePath("VMSstreamerQt");
}

QString MainWindow::defaultLocalFile() const {
    const QString path = locateFile(kDataFileName);
    return path;
}

void MainWindow::updateSaveControls() {
    const bool enabled = saveFtpCheck_ && saveFtpCheck_->isChecked();
    if (saveDirEdit_) saveDirEdit_->setEnabled(enabled);
    if (browseSaveDirButton_) browseSaveDirButton_->setEnabled(enabled);
}

void MainWindow::updateSourceControls() {
    const bool useFtp = useFtpCheck_ && useFtpCheck_->isChecked();
    if (localFileEdit_) localFileEdit_->setEnabled(!useFtp);
    if (browseLocalFileButton_) browseLocalFileButton_->setEnabled(!useFtp);

    if (saveFtpCheck_) {
        saveFtpCheck_->setEnabled(useFtp);
        if (!useFtp) {
            saveFtpCheck_->setChecked(false);
        }
    }
    updateSaveControls();
}

void MainWindow::chooseSaveDir() {
    QString start = saveDirEdit_ ? saveDirEdit_->text().trimmed() : QString();
    if (start.isEmpty()) {
        start = defaultSaveDir();
    }
    const QString dir = QFileDialog::getExistingDirectory(this, "Choose Save Directory", start);
    if (!dir.isEmpty() && saveDirEdit_) {
        saveDirEdit_->setText(dir);
    }
}

void MainWindow::chooseLocalFile() {
    QString start = localFileEdit_ ? localFileEdit_->text().trimmed() : QString();
    if (start.isEmpty()) {
        start = locateFile(kDataFileName);
    }
    const QString path = QFileDialog::getOpenFileName(
        this,
        "Choose CSV File",
        start,
        "CSV Files (*.csv);;All Files (*)");
    if (!path.isEmpty() && localFileEdit_) {
        localFileEdit_->setText(path);
    }
}

bool MainWindow::downloadFtpFile(const QString &host,
                                 const QString &user,
                                 const QString &pass,
                                 QByteArray *out,
                                 QString *error) const {
    QString url = host.trimmed();
    const bool hasScheme = url.startsWith("ftp://", Qt::CaseInsensitive)
        || url.startsWith("ftps://", Qt::CaseInsensitive);
    if (hasScheme) {
        if (url.startsWith("ftps://", Qt::CaseInsensitive)) {
            if (error) {
                *error = "FTPS is not supported. Use plain FTP (ftp://) or remove the scheme.";
            }
            return false;
        }
    } else {
        url = QString("ftp://%1").arg(url);
    }
    if (!url.endsWith('/')) {
        url.append('/');
    }
    url.append(kDataFileName);

    CURL *curl = curl_easy_init();
    if (!curl) {
        if (error) {
            *error = "Failed to initialize FTP client.";
        }
        return false;
    }

    QByteArray buffer;

    curl_easy_setopt(curl, CURLOPT_URL, url.toUtf8().constData());
    curl_easy_setopt(curl, CURLOPT_USERNAME, user.toUtf8().constData());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, pass.toUtf8().constData());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToBuffer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);

    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        if (error) {
            *error = QString("FTP download failed: %1").arg(curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
        return false;
    }

    curl_easy_cleanup(curl);
    if (out) {
        *out = buffer;
    }
    return true;
}

bool MainWindow::loadCsvFromDevice(QIODevice *device, TableData *out, QString *error) const {
    if (!device || !out) {
        if (error) {
            *error = "Invalid CSV input.";
        }
        return false;
    }

    QTextStream in(device);
    int lineNumber = 0;
    const QSet<int> skipLines = {0, 2, 3};
    QStringList headers;
    QVector<QStringList> rows;

    while (!in.atEnd()) {
        QString line = in.readLine();
        if (line.endsWith('\r')) {
            line.chop(1);
        }

        if (skipLines.contains(lineNumber)) {
            ++lineNumber;
            continue;
        }

        const QStringList fields = parseCsvLine(line);
        if (headers.isEmpty()) {
            headers = fields;
        } else if (fields.size() == headers.size()) {
            rows.append(fields);
        }

        ++lineNumber;
    }

    if (headers.isEmpty()) {
        if (error) {
            *error = "CSV file is empty or missing headers.";
        }
        return false;
    }

    out->headers = headers;
    out->rows = rows;
    out->timestampIndex = headers.indexOf(kTimestampColumn);
    return true;
}

QStringList MainWindow::parseCsvLine(const QString &line) const {
    QStringList fields;
    QString current;
    bool inQuotes = false;

    for (int i = 0; i < line.size(); ++i) {
        const QChar ch = line.at(i);
        if (inQuotes) {
            if (ch == '"') {
                const bool nextIsQuote = (i + 1 < line.size() && line.at(i + 1) == '"');
                if (nextIsQuote) {
                    current.append('"');
                    ++i;
                } else {
                    inQuotes = false;
                }
            } else {
                current.append(ch);
            }
        } else {
            if (ch == '"') {
                inQuotes = true;
            } else if (ch == ',') {
                fields.append(current);
                current.clear();
            } else {
                current.append(ch);
            }
        }
    }

    fields.append(current);
    return fields;
}

QDateTime MainWindow::parseTimestamp(const QString &text) const {
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }

    QDateTime dt = QDateTime::fromString(trimmed, Qt::ISODateWithMs);
    if (!dt.isValid()) {
        dt = QDateTime::fromString(trimmed, Qt::ISODate);
    }
    if (!dt.isValid()) {
        dt = QDateTime::fromString(trimmed, "yyyy-MM-dd HH:mm:ss");
    }
    if (!dt.isValid()) {
        dt = QDateTime::fromString(trimmed, "yyyy/MM/dd HH:mm:ss");
    }
    if (!dt.isValid()) {
        dt = QDateTime::fromString(trimmed, "dd/MM/yyyy HH:mm:ss");
    }

    if (dt.isValid() && dt.timeSpec() == Qt::LocalTime) {
        return dt;
    }

    return dt;
}

void MainWindow::populateVariables() {
    varList_->clear();

    for (const QString &header : data_.headers) {
        if (header == kTimestampColumn || header == kRecordColumn) {
            continue;
        }
        varList_->addItem(header);
    }

    for (int i = 0; i < varList_->count() && i < 3; ++i) {
        varList_->item(i)->setSelected(true);
    }
}

void MainWindow::populatePreview() {
    previewTable_->clear();

    if (data_.headers.isEmpty()) {
        previewTable_->setRowCount(0);
        previewTable_->setColumnCount(0);
        return;
    }

    const int rowCount = std::min(kPreviewRowCount, static_cast<int>(data_.rows.size()));
    previewTable_->setColumnCount(data_.headers.size());
    previewTable_->setRowCount(rowCount);
    previewTable_->setHorizontalHeaderLabels(data_.headers);

    for (int row = 0; row < rowCount; ++row) {
        const QStringList &rowData = data_.rows.at(row);
        for (int col = 0; col < data_.headers.size(); ++col) {
            const QString value = (col < rowData.size()) ? rowData.at(col) : QString();
            auto *item = new QTableWidgetItem(value);
            previewTable_->setItem(row, col, item);
        }
    }

    previewTable_->resizeColumnsToContents();
}

void MainWindow::loadData(bool quiet) {
    statusLabel_->setText("Loading data...");
    QCoreApplication::processEvents();

    TableData loaded;
    QString error;

    if (useFtpCheck_->isChecked()) {
        QString host;
        QString user;
        QString pass;
        if (!loadCredentials(&host, &user, &pass, &error)) {
            statusLabel_->setText("Load failed");
            if (!quiet) {
                QMessageBox::critical(this, "Load Error", error);
            }
            return;
        }

        QByteArray payload;
        if (!downloadFtpFile(host, user, pass, &payload, &error)) {
            statusLabel_->setText("Load failed");
            if (!quiet) {
                QMessageBox::critical(this, "FTP Error", error);
            }
            return;
        }

        if (saveFtpCheck_ && saveFtpCheck_->isChecked()) {
            QString dirPath = saveDirEdit_ ? saveDirEdit_->text().trimmed() : QString();
            if (dirPath.isEmpty()) {
                dirPath = defaultSaveDir();
                if (saveDirEdit_) {
                    saveDirEdit_->setText(dirPath);
                }
            }
            QDir dir(dirPath);
            if (!dir.exists() && !dir.mkpath(".")) {
                statusLabel_->setText("Save failed");
                QMessageBox::critical(this, "Save Error",
                                      QString("Failed to create directory: %1").arg(dirPath));
                return;
            }

            const QString filePath = dir.filePath(kDataFileName);
            QSaveFile outFile(filePath);
            if (!outFile.open(QIODevice::WriteOnly)) {
                statusLabel_->setText("Save failed");
                QMessageBox::critical(this, "Save Error",
                                      QString("Failed to write file: %1").arg(outFile.errorString()));
                return;
            }
            outFile.write(payload);
            if (!outFile.commit()) {
                statusLabel_->setText("Save failed");
                QMessageBox::critical(this, "Save Error",
                                      QString("Failed to save file: %1").arg(outFile.errorString()));
                return;
            }
        }

        QBuffer buffer(&payload);
        buffer.open(QIODevice::ReadOnly);
        if (!loadCsvFromDevice(&buffer, &loaded, &error)) {
            statusLabel_->setText("Load failed");
            if (!quiet) {
                QMessageBox::critical(this, "CSV Error", error);
            }
            return;
        }
    } else {
        QString path = localFileEdit_ ? localFileEdit_->text().trimmed() : QString();
        if (path.isEmpty()) {
            path = locateFile(kDataFileName);
        }
        if (path.isEmpty()) {
            statusLabel_->setText("No local file selected");
            if (!quiet) {
                QMessageBox::information(this, "Load Data", "Select a local CSV file to load.");
            }
            return;
        }

        QFile file(path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            statusLabel_->setText("Load failed");
            if (!quiet) {
                QMessageBox::critical(this, "Load Error",
                                      QString("Failed to open file: %1").arg(file.errorString()));
            }
            return;
        }

        if (!loadCsvFromDevice(&file, &loaded, &error)) {
            statusLabel_->setText("Load failed");
            if (!quiet) {
                QMessageBox::critical(this, "CSV Error", error);
            }
            return;
        }
    }

    data_ = std::move(loaded);
    statusLabel_->setText(QString("Loaded %1 rows").arg(data_.rows.size()));
    populateVariables();
    populatePreview();

    resetChart();
}

void MainWindow::plotSelected() {
    if (data_.rows.isEmpty() || data_.headers.isEmpty()) {
        QMessageBox::warning(this, "No data", "Load data before plotting.");
        return;
    }

    const QList<QListWidgetItem *> selectedItems = varList_->selectedItems();
    if (selectedItems.isEmpty()) {
        QMessageBox::warning(this, "No selection", "Select at least one variable to plot.");
        return;
    }

    const bool hasTimestamp = data_.timestampIndex >= 0;

    auto *chart = new QChart();
    chart->setTitle("Selected Data Plot");

    bool hasPoint = false;
    double minY = 0.0;
    double maxY = 0.0;
    double minX = 0.0;
    double maxX = 0.0;
    qint64 minXms = 0;
    qint64 maxXms = 0;

    for (QListWidgetItem *item : selectedItems) {
        const QString seriesName = item->text();
        const int colIndex = data_.headers.indexOf(seriesName);
        if (colIndex < 0) {
            continue;
        }

        auto *series = new QLineSeries();
        series->setName(seriesName);

        for (int rowIndex = 0; rowIndex < data_.rows.size(); ++rowIndex) {
            const QStringList &row = data_.rows.at(rowIndex);
            if (row.size() <= colIndex) {
                continue;
            }

            bool yOk = false;
            const double yValue = row.at(colIndex).toDouble(&yOk);
            if (!yOk) {
                continue;
            }

            if (hasTimestamp) {
                const QString tsText = row.at(data_.timestampIndex);
                const QDateTime dt = parseTimestamp(tsText);
                if (!dt.isValid()) {
                    continue;
                }
                const qint64 xValue = dt.toMSecsSinceEpoch();
                series->append(static_cast<qreal>(xValue), yValue);

                if (!hasPoint) {
                    minXms = maxXms = xValue;
                    minY = maxY = yValue;
                    hasPoint = true;
                } else {
                    minXms = std::min(minXms, xValue);
                    maxXms = std::max(maxXms, xValue);
                    minY = std::min(minY, yValue);
                    maxY = std::max(maxY, yValue);
                }
            } else {
                const double xValue = static_cast<double>(rowIndex);
                series->append(xValue, yValue);

                if (!hasPoint) {
                    minX = maxX = xValue;
                    minY = maxY = yValue;
                    hasPoint = true;
                } else {
                    minX = std::min(minX, xValue);
                    maxX = std::max(maxX, xValue);
                    minY = std::min(minY, yValue);
                    maxY = std::max(maxY, yValue);
                }
            }
        }

        chart->addSeries(series);
    }

    if (!hasPoint) {
        delete chart;
        QMessageBox::warning(this, "No data", "No numeric data available to plot.");
        return;
    }

    if (minY == maxY) {
        minY -= 1.0;
        maxY += 1.0;
    }

    if (hasTimestamp) {
        if (minXms == maxXms) {
            minXms -= 60000;
            maxXms += 60000;
        }
        auto *axisX = new QDateTimeAxis();
        axisX->setFormat("yyyy-MM-dd HH:mm");
        axisX->setTitleText(kTimestampColumn);
        axisX->setRange(QDateTime::fromMSecsSinceEpoch(minXms),
                        QDateTime::fromMSecsSinceEpoch(maxXms));
        chart->addAxis(axisX, Qt::AlignBottom);
        for (QAbstractSeries *series : chart->series()) {
            series->attachAxis(axisX);
        }
    } else {
        if (minX == maxX) {
            minX -= 1.0;
            maxX += 1.0;
        }
        auto *axisX = new QValueAxis();
        axisX->setTitleText("Index");
        axisX->setRange(minX, maxX);
        chart->addAxis(axisX, Qt::AlignBottom);
        for (QAbstractSeries *series : chart->series()) {
            series->attachAxis(axisX);
        }
    }

    auto *axisY = new QValueAxis();
    axisY->setTitleText("Values");
    axisY->setRange(minY, maxY);
    chart->addAxis(axisY, Qt::AlignLeft);
    for (QAbstractSeries *series : chart->series()) {
        series->attachAxis(axisY);
    }

    chartView_->setChart(chart);
    chartView_->setVisible(true);
}

void MainWindow::savePlot() {
    if (!chartView_->isVisible() || !chartView_->chart()) {
        QMessageBox::warning(this, "No plot", "Create a plot before saving.");
        return;
    }

    QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (defaultDir.isEmpty()) {
        defaultDir = QDir::homePath();
    }

    const QString defaultPath = QDir(defaultDir).filePath("vms_plot.png");
    QString selectedFilter;
    const QString path = QFileDialog::getSaveFileName(
        this,
        "Save Plot",
        defaultPath,
        "PNG Image (*.png);;PDF Document (*.pdf)",
        &selectedFilter);

    if (path.isEmpty()) {
        return;
    }

    const bool wantsPdf = selectedFilter.contains("PDF", Qt::CaseInsensitive)
        || path.endsWith(".pdf", Qt::CaseInsensitive);

    if (wantsPdf) {
        QString pdfPath = path;
        if (!pdfPath.endsWith(".pdf", Qt::CaseInsensitive)) {
            pdfPath.append(".pdf");
        }

        QPdfWriter writer(pdfPath);
        writer.setPageSize(QPageSize(QPageSize::A4));
        writer.setPageMargins(QMarginsF(15, 15, 15, 15));
        QPainter painter(&writer);
        if (!painter.isActive()) {
            QMessageBox::critical(this, "Save Error", "Failed to create PDF writer.");
            return;
        }
        chartView_->render(&painter);
        painter.end();
    } else {
        QString pngPath = path;
        if (!pngPath.endsWith(".png", Qt::CaseInsensitive)) {
            pngPath.append(".png");
        }

        const QPixmap pixmap = chartView_->grab();
        if (!pixmap.save(pngPath, "PNG")) {
            QMessageBox::critical(this, "Save Error", "Failed to save PNG file.");
            return;
        }
    }
}

void MainWindow::resetChart() {
    if (!chartView_) {
        return;
    }
    QChart *chart = chartView_->chart();
    if (!chart) {
        chart = new QChart();
        chartView_->setChart(chart);
    } else {
        chart->removeAllSeries();
        const auto axes = chart->axes();
        for (auto *axis : axes) {
            chart->removeAxis(axis);
        }
    }
    chart->setTitle("Selected Data Plot");
    chartView_->setVisible(false);
}
