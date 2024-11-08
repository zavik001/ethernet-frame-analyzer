#include <iostream>
#include <vector>
#include <fstream>
#include <windows.h>
#include <map>
#include <iomanip>

using namespace std;

// Функция для чтения файла и записи его содержимого в вектор
vector<UCHAR> readFile(const string& filename, int& fileSize) {
    // Открываем файл в двоичном режиме
    ifstream in(filename, ios::binary);
    if (!in.is_open()) {
        cerr << "Error opening file!" << endl;
        exit(1);
    }
    
    // Определяем размер файла
    in.seekg(0, ios_base::end);
    fileSize = in.tellg();
    in.seekg(0);

    // Считываем данные файла в вектор
    vector<UCHAR> data((istreambuf_iterator<char>(in)), {});
    in.close();

    return data;
}

// Функция для вывода MAC-адреса в поток
void printMacAddress(ofstream& out, const vector<UCHAR>& data, int start) {
    // Выводим 6 байтов MAC-адреса с разделителем ':'
    for (int i = 0; i < 5; i++) {
        out << setw(2) << setfill('0') << hex << uppercase << (int)data[start + i] << ':';
    }
    // Последний байт MAC-адреса без завершающего двоеточия
    out << setw(2) << setfill('0') << (int)data[start + 5] << endl;
}

// Функция для вывода IP-адреса в поток
void printIpAddress(ofstream& out, const vector<UCHAR>& data, int start) {
    out << dec;
    // Выводим 4 байта IP-адреса с разделителем '.'
    for (int i = 0; i < 3; i++) {
        out << (int)data[start + i] << '.';
    }
    // Последний байт IP-адреса без завершающей точки
    out << (int)data[start + 3] << endl;
}

// Обработка фрейма типа IPv4
void handleIPv4Frame(ofstream& out, const vector<UCHAR>& data, int& byte, map<string, UCHAR>& frameNumber) {
    frameNumber["IPv4"]++;  // Увеличиваем счётчик IPv4 фреймов
    out << "Protocol: IPv4" << endl;

    // Печать IP-адреса отправителя
    out << "IP address of the sender: ";
    printIpAddress(out, data, byte + 26);

    // Печать IP-адреса получателя
    out << "IP address of the recipient: ";
    printIpAddress(out, data, byte + 30);

    // Определяем размер пакета и смещаем указатель на следующий фрейм
    USHORT frameSize = (data[byte + 16] << 8) + data[byte + 17] + 14;
    out << "Package Size: " << frameSize << " byte" << endl;
    byte += frameSize;
}

// Обработка фрейма типа ARP
void handleARPFrame(ofstream& out, const vector<UCHAR>& data, int& byte, map<string, UCHAR>& frameNumber) {
    frameNumber["ARP"]++;  // Увеличиваем счётчик ARP фреймов
    out << "Type of frame: ARP" << endl;

    // Печать MAC-адреса отправителя
    out << "MAC address of the sender: ";
    printMacAddress(out, data, byte + 22);

    // Печать IP-адреса отправителя
    out << "IP address of the sender: ";
    printIpAddress(out, data, byte + 28);

    // Печать MAC-адреса получателя
    out << "MAC address of the recipient: ";
    printMacAddress(out, data, byte + 32);

    // Печать IP-адреса получателя
    out << "IP address of the recipient: ";
    printIpAddress(out, data, byte + 38);

    byte += 42;  // Смещение указателя на следующий фрейм
}

// Определение типа фрейма и его обработка
void processFrame(ofstream& out, const vector<UCHAR>& data, int& byte, map<string, UCHAR>& frameNumber) {
    // Определяем тип фрейма по значениям в заголовке
    USHORT BN = (data[byte + 12] << 8) + data[byte + 13];

    if (BN > 0x05DC) {  // Ethernet II кадр
        out << "Type of frame: DIX (Ethernet II)" << endl;
        frameNumber["DIX"]++;  // Увеличиваем счётчик DIX фреймов

        // Обработка IPv4 и ARP фреймов
        if (BN == 0x0800) {
            handleIPv4Frame(out, data, byte, frameNumber);
        } else if (BN == 0x0806) {
            handleARPFrame(out, data, byte, frameNumber);
        } else {
            byte += BN + 14;  // Пропуск фрейма неизвестного типа
        }
    } else {  // 802.3 кадр
        USHORT LLC = (data[byte + 14] << 8) + data[byte + 15];
        if (LLC == 0xFFFF) {
            frameNumber["RAW"]++;
            out << "Type of frame: Ethernet Raw 802.3" << endl;
        } else if (LLC == 0xAAAA) {
            frameNumber["SNAP"]++;
            out << "Type of frame: Ethernet SNAP" << endl;
        } else {
            frameNumber["LLC"]++;
            out << "Type of frame: Ethernet 802.2/LLC" << endl;
        }
        byte += BN + 14;
    }
}

// Основная функция для обработки всех кадров
void analyzeFrames(const vector<UCHAR>& data, ofstream& out, map<string, UCHAR>& frameNumber) {
    int byte = 0;
    int frameCount = 0;

    while (byte < data.size()) {
        frameCount++;
        out << "Frame №: " << frameCount << endl;

        // Печать MAC-адреса получателя
        out << "MAC address of the recipient: ";
        printMacAddress(out, data, byte);

        // Печать MAC-адреса отправителя
        out << "MAC address of the sender: ";
        printMacAddress(out, data, byte + 6);

        // Обработка текущего фрейма
        processFrame(out, data, byte, frameNumber);
        out << endl;
    }

    // Итоговый отчет
    out << "Total frames: " << frameCount << endl << endl;
    out << "Type of frames:" << endl;
    for (const auto& frame : frameNumber) {
        out << frame.first << (int)frame.second << endl;
    }
}

int main() {
    // Установка кодировки для консоли
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    // Счетчики для различных типов фреймов
    map<string, UCHAR> frameNumber = {{"IPv4: ", 0}, {"DIX: ", 0}, {"RAW: ", 0}, {"SNAP: ", 0}, {"LLC: ", 0}, {"ARP: ", 0}};

    // Ввод имени файла
    string filename;
    cout << "Input filename: ";
    cin >> filename;

    // Чтение данных файла
    int fileSize;
    vector<UCHAR> data = readFile(filename, fileSize);

    // Создание выходного файла для записи результатов
    ofstream out("../data/frames_info.txt");
    out << "File size of " << filename << " is " << fileSize << " byte" << endl << endl;

    // Анализ и обработка фреймов
    analyzeFrames(data, out, frameNumber);
    
    out.close();
    cout << "The program has finished working!";
    return 0;
}
