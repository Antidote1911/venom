#pragma once
#include <QDialog>
#include <QListWidget>
#include <QLineEdit>
#include <QCheckBox>
#include "../backend/VenomCore.h"

namespace Venom {

class KeyManagerDialog : public QDialog {
    Q_OBJECT
public:
    explicit KeyManagerDialog(VenomCore* core, QWidget* parent = nullptr);

private slots:
    void onGenerate();
    void onImport();
    void onExportPub();
    void onDelete();
    void onRefresh();

private:
    VenomCore*   m_core;
    QListWidget* m_keyList;
    QLineEdit*   m_labelEdit;
    QLineEdit*   m_passphraseEdit;
    QCheckBox*   m_sensitiveCheck;
    QList<KeyEntry> m_keys;
};

} // namespace Venom
