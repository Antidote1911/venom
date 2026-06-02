#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QSpinBox>
#include <QComboBox>
#include <QButtonGroup>
#include <QCheckBox>
#include <QGroupBox>
#include "../backend/VenomCore.h"

namespace Venom {

class CreateDialog : public QDialog {
    Q_OBJECT
public:
    explicit CreateDialog(VenomCore* core, QWidget* parent = nullptr);

private slots:
    void onAccepted();
    void onBrowse();

private:
    VenomCore*   m_core;
    QLineEdit*   m_path;
    QLineEdit*   m_label;
    QSpinBox*    m_size;
    QLineEdit*   m_password;
    QLineEdit*   m_confirm;
    QComboBox*   m_cipher;
    QButtonGroup* m_kdf;
    QCheckBox*   m_hiddenCheck;
    QGroupBox*   m_hiddenBox;
    QSpinBox*    m_hiddenSize;
    QLineEdit*   m_hiddenPw;
    QLineEdit*   m_hiddenConfirm;
};

} // namespace Venom
