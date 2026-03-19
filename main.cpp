#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>

using namespace std;


// 定义节表数据结构
typedef struct SectionTable {
    DWORD myVirtualAddress;      // 区段在内存中的起始RVA（相对虚拟地址）
    DWORD myPointerToRawData;    // 区段在磁盘文件中的起始偏移地址
    DWORD mySizeOfRawData;       // 区段在磁盘文件中占用的大小
    string myName;               // 区段名称
} SECTION_TABLE, *PSECTION_TABLE;

// PE 文件的基础加载信息
typedef struct BaseData {
    ULONGLONG myImageBase;       // 程序加载到内存的基地址（64位支持）
    DWORD mySectionAlignment;    // 内存中区段的对齐单位
    DWORD myFileAlignment;       // 磁盘文件中区段的对齐单位
    BOOL isDll;                  // 是否为动态链接库
    BOOL is64Bit;                // 是否为64位PE文件
} BASE_DATA, *PBASE_DATA;

// 数据目录表（Data Directory Table）
typedef struct TableAddress {
    DWORD myVirtualAddress;      // 表在内存中的起始RVA
    DWORD mySize;                // 表的大小（字节）
    string myName;               // 表的名称
} TABLE_ADDRESS, *PTABLE_ADDRESS;

// 全局变量
vector<SectionTable> g_sectionTable;    //存储 PE 文件中所有区段 的数据
vector<TableAddress> g_tableAddress;   //存储 PE 文件中所有 ** 数据目录表（Data Directory）** 的位置和大小
BaseData g_baseData;                   //存储 PE 文件的基础加载信息，决定文件如何从磁盘映射到内存
char* g_peFileBuffer = NULL;            //存储 PE 文件的原始二进制数据
DWORD g_peFileSize = 0;               //记录 PE 文件的大小
string g_filePath;                      //存储 PE 文件的完整路径

// 函数声明
void showMainMenu();
void showHeaderInfo();
void showSectionInfo();
void showExportInfo();
void showImportInfo();
void showRawData(DWORD offset, DWORD size);
string formatHexData(const char* data, DWORD size);
DWORD rvaToFoa(DWORD rva);
void parsePeFile(const char* filePath);
void cleanup();

int main(int argc, char* argv[]) {
    // 建议注释掉这句，避免和本地编译器的GBK编码冲突导致乱码
    // SetConsoleOutputCP(65001); 

    char pathBuf[MAX_PATH];
    
    if (argc != 2) {
        // 如果没有命令行参数，改为提示用户手动输入
        printf("请输入需要分析的 PE 文件绝对路径: ");
        scanf("%259s", pathBuf); // 限制读取长度防止溢出
        g_filePath = pathBuf;
    } else {
        // 如果有命令行参数（比如拖拽文件到exe上），正常接收
        g_filePath = argv[1];
    }

    parsePeFile(g_filePath.c_str());
    showMainMenu();
    cleanup();
    return 0;
}

void parsePeFile(const char* filePath) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("无法打开文件: %s\n", filePath);
        exit(1);
    }

    g_peFileSize = GetFileSize(hFile, NULL);
    if (g_peFileSize == INVALID_FILE_SIZE) {
        printf("获取文件大小失败: %s\n", filePath);
        CloseHandle(hFile);
        exit(1);
    }

    g_peFileBuffer = new (nothrow) char[g_peFileSize]();
    if (!g_peFileBuffer) {
        printf("内存分配失败，文件大小: %u bytes\n", g_peFileSize);
        CloseHandle(hFile);
        exit(1);
    }
        //读取文件内容到内存
    DWORD bytesRead;
    if (!ReadFile(hFile, g_peFileBuffer, g_peFileSize, &bytesRead, NULL) || bytesRead != g_peFileSize) {
        printf("无法读取文件: %s (读取了 %u/%u 字节)\n", filePath, bytesRead, g_peFileSize);
        delete[] g_peFileBuffer;
        g_peFileBuffer = NULL;
        CloseHandle(hFile);
        exit(1);
    }
    CloseHandle(hFile);

    // 检查DOS头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_peFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {                     //e_magic必须为0x5A4D
        printf("不是有效的PE文件（缺少DOS头）\n");
        exit(1);
    }

    // 检查NT头
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(g_peFileBuffer + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {        //Signature必须为0x00004550
        printf("不是有效的PE文件（缺少NT头）\n");
        exit(1);
    }

    // 确定是32位还是64位PE文件
    g_baseData.is64Bit = (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // 设置基本数据
    g_baseData.myImageBase = pNtHeader->OptionalHeader.ImageBase;               //文件加载的首选基址
    g_baseData.mySectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;//内存中区段的对齐单位
    g_baseData.myFileAlignment = pNtHeader->OptionalHeader.FileAlignment;     //磁盘中区段的对齐单位
    g_baseData.isDll = (pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    // 解析数据目录
    IMAGE_DATA_DIRECTORY* dataDirectory;
    if (g_baseData.is64Bit) {
        PIMAGE_NT_HEADERS64 pNtHeader64 = (PIMAGE_NT_HEADERS64)pNtHeader;
        dataDirectory = pNtHeader64->OptionalHeader.DataDirectory;
    } else {
        PIMAGE_NT_HEADERS32 pNtHeader32 = (PIMAGE_NT_HEADERS32)pNtHeader;
        dataDirectory = pNtHeader32->OptionalHeader.DataDirectory;
    }

    const char* directoryNames[] = {
        "导出表", "导入表", "资源表", "异常表",
        "安全表", "基址重定位表", "调试信息", "架构信息",
        "全局指针", "TLS表", "加载配置表", "绑定导入",
        "IAT表", "延迟导入", "COM描述符", "保留"
    };

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        if (dataDirectory[i].VirtualAddress != 0) {
            TableAddress tableAddr;
            tableAddr.myVirtualAddress = dataDirectory[i].VirtualAddress;
            tableAddr.mySize = dataDirectory[i].Size;
            tableAddr.myName = directoryNames[i];
            g_tableAddress.push_back(tableAddr);
        }
    }

    // 解析节表
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        SectionTable section;
        section.myVirtualAddress = sectionHeader->VirtualAddress;
        section.myPointerToRawData = sectionHeader->PointerToRawData;
        section.mySizeOfRawData = sectionHeader->SizeOfRawData;
        section.myName = string((char*)sectionHeader->Name, 8);
        g_sectionTable.push_back(section);
        sectionHeader++;
    }
}

void showMainMenu() {
    int choice = 0;
    do {
        system("cls");
        printf("========== PE文件分析器 ==========\n");
        printf("文件: %s\n", g_filePath.c_str());
        printf("大小: %u 字节 (0x%X)\n", g_peFileSize, g_peFileSize);
        printf("类型: %s\n", g_baseData.isDll ? "DLL" : "EXE");
        printf("位数: %s\n", g_baseData.is64Bit ? "64位" : "32位");
        // 根据PE位数正确显示镜像基址
        if (g_baseData.is64Bit) {
            printf("镜像基址: 0x%llX\n", g_baseData.myImageBase);
        } else {
            printf("镜像基址: 0x%08X\n", (DWORD)g_baseData.myImageBase);
        }
        printf("\n菜单选项:\n");
        printf("1. 显示PE头信息\n");
        printf("2. 显示节表信息\n");
        printf("3. 显示导出表信息\n");
        printf("4. 显示导入表信息\n");
        printf("5. 按偏移量查看原始数据\n");
        printf("0. 退出\n");
        printf("======================================\n");
        printf("请输入您的选择: ");
        scanf("%d", &choice);

        switch (choice) {
        case 1: showHeaderInfo(); break;
        case 2: showSectionInfo(); break;
        case 3: showExportInfo(); break;
        case 4: showImportInfo(); break;
        case 5: {
            DWORD offset, size;
            printf("输入偏移量(十六进制): ");
            scanf("%x", &offset);
            printf("输入大小(十六进制): ");
            scanf("%x", &size);
            showRawData(offset, size);
            break;
        }
        case 0: break;
        default: printf("无效选择!\n"); Sleep(1000); break;
        }
    } while (choice != 0);
}

void showHeaderInfo() {
    system("cls");
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_peFileBuffer;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(g_peFileBuffer + pDosHeader->e_lfanew);

    printf("========== PE头信息 ==========\n");
    printf("\nDOS头:\n");
    printf("魔术数字(MZ): 0x%X\n", pDosHeader->e_magic);
    printf("PE头偏移: 0x%X\n", pDosHeader->e_lfanew);

    printf("\nNT头:\n");
    printf("签名(PE): 0x%X\n", pNtHeader->Signature);

    printf("\n文件头:\n");
    printf("机器类型: 0x%X\n", pNtHeader->FileHeader.Machine);
    printf("节数量: %d\n", pNtHeader->FileHeader.NumberOfSections);
    printf("时间戳: 0x%X\n", pNtHeader->FileHeader.TimeDateStamp);
    printf("特征值: 0x%X\n", pNtHeader->FileHeader.Characteristics);

    printf("\n可选头:\n");
    printf("魔术数字: 0x%X (%s)\n", pNtHeader->OptionalHeader.Magic,
           pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "64位" : "32位");

    if (g_baseData.is64Bit) {
        PIMAGE_NT_HEADERS64 pNtHeader64 = (PIMAGE_NT_HEADERS64)pNtHeader;
        printf("入口点地址: 0x%X\n", pNtHeader64->OptionalHeader.AddressOfEntryPoint);
        printf("镜像基址: 0x%llX\n", pNtHeader64->OptionalHeader.ImageBase);
        printf("节对齐: 0x%X\n", pNtHeader64->OptionalHeader.SectionAlignment);
        printf("文件对齐: 0x%X\n", pNtHeader64->OptionalHeader.FileAlignment);
        printf("镜像大小: 0x%X\n", pNtHeader64->OptionalHeader.SizeOfImage);
        printf("头大小: 0x%X\n", pNtHeader64->OptionalHeader.SizeOfHeaders);
        printf("子系统: 0x%X\n", pNtHeader64->OptionalHeader.Subsystem);
        printf("DLL特征: 0x%X\n", pNtHeader64->OptionalHeader.DllCharacteristics);
    } else {
        PIMAGE_NT_HEADERS32 pNtHeader32 = (PIMAGE_NT_HEADERS32)pNtHeader;
        printf("入口点地址: 0x%X\n", pNtHeader32->OptionalHeader.AddressOfEntryPoint);
        printf("镜像基址: 0x%08X\n", pNtHeader32->OptionalHeader.ImageBase);
        printf("节对齐: 0x%X\n", pNtHeader32->OptionalHeader.SectionAlignment);
        printf("文件对齐: 0x%X\n", pNtHeader32->OptionalHeader.FileAlignment);
        printf("镜像大小: 0x%X\n", pNtHeader32->OptionalHeader.SizeOfImage);
        printf("头大小: 0x%X\n", pNtHeader32->OptionalHeader.SizeOfHeaders);
        printf("子系统: 0x%X\n", pNtHeader32->OptionalHeader.Subsystem);
        printf("DLL特征: 0x%X\n", pNtHeader32->OptionalHeader.DllCharacteristics);
    }

    printf("\n数据目录:\n");
    for (size_t i = 0; i < g_tableAddress.size(); i++) {
        printf("%2d. %-20s RVA: 0x%08X  大小: 0x%08X\n",
               i+1, g_tableAddress[i].myName.c_str(),
               g_tableAddress[i].myVirtualAddress,
               g_tableAddress[i].mySize);
    }

    printf("\n按回车键返回主菜单...");
    getchar(); getchar();
}

void showSectionInfo() {
    system("cls");
    printf("========== 节表信息 ==========\n");
    printf("%-8s %-10s %-10s %-10s %s\n",
           "节名", "虚拟地址", "文件偏移", "大小", "原始数据");
    printf("------------------------------------------------\n");

    for (size_t i = 0; i < g_sectionTable.size(); i++) {
        printf("%-8s 0x%08X 0x%08X 0x%08X ",
               g_sectionTable[i].myName.c_str(),
               g_sectionTable[i].myVirtualAddress,
               g_sectionTable[i].myPointerToRawData,
               g_sectionTable[i].mySizeOfRawData);
        // 计算并显示节的前16字节原始数据
        DWORD size = min(g_sectionTable[i].mySizeOfRawData, static_cast<DWORD>(16));
        //安全边界检查
        if (g_sectionTable[i].myPointerToRawData + size <= g_peFileSize) {
            string hexData = formatHexData(g_peFileBuffer + g_sectionTable[i].myPointerToRawData, size);
            //将格式化后的十六进制数据字符串输出到控制台
            printf("%s", hexData.c_str());
        }
        printf("\n");
    }

    printf("\n按回车键返回主菜单...");
    getchar();  //清除缓冲区的\n，否则会直接跳转
    getchar();
}

void showExportInfo() {
    // 清屏，为显示导出表信息做准备
    system("cls");
    printf("========== 导出表信息 ==========\n");

    // 检查导出表是否存在
    // IMAGE_DIRECTORY_ENTRY_EXPORT 是导出表在数据目录中的索引
    if (g_tableAddress.size() <= IMAGE_DIRECTORY_ENTRY_EXPORT ||
        g_tableAddress[IMAGE_DIRECTORY_ENTRY_EXPORT].myVirtualAddress == 0) {
        printf("未找到导出表。\n");
        printf("\n按回车键返回主菜单...");
        getchar(); getchar(); // 等待用户按下回车键后返回主菜单
        return;
    }

    // 获取导出表的RVA（相对虚拟地址）
    DWORD exportRva = g_tableAddress[IMAGE_DIRECTORY_ENTRY_EXPORT].myVirtualAddress;
    // 将RVA转换为FOA（文件偏移地址）
    DWORD exportFoa = rvaToFoa(exportRva);
    // 获取导出目录结构的指针
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(g_peFileBuffer + exportFoa);

    // 获取DLL名称的RVA，并转换为FOA
    DWORD nameRva = exportDir->Name;
    DWORD nameFoa = rvaToFoa(nameRva);
    // 获取DLL名称的指针
    char* dllName = (char*)(g_peFileBuffer + nameFoa);

    // 显示导出表的基本信息
    printf("DLL名称: %s\n", dllName);
    printf("函数数量: %d\n", exportDir->NumberOfFunctions);
    printf("名称数量: %d\n", exportDir->NumberOfNames);
    printf("基址: %d\n", exportDir->Base);

    // 获取导出函数的地址数组、名称数组和序号数组的指针
    DWORD* functions = (DWORD*)(g_peFileBuffer + rvaToFoa(exportDir->AddressOfFunctions));
    DWORD* names = (DWORD*)(g_peFileBuffer + rvaToFoa(exportDir->AddressOfNames));
    WORD* ordinals = (WORD*)(g_peFileBuffer + rvaToFoa(exportDir->AddressOfNameOrdinals));

    // 显示导出函数的详细信息
    printf("\n导出函数:\n");
    printf("%-8s %-30s %s\n", "序号", "名称", "RVA");
    printf("------------------------------------------------\n");

    // 遍历导出函数的名称数组
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        // 获取函数名称的RVA，并转换为FOA
        DWORD nameRva = names[i];
        DWORD nameFoa = rvaToFoa(nameRva);
        // 获取函数名称的指针
        char* funcName = (char*)(g_peFileBuffer + nameFoa);
        // 获取函数的序号
        WORD ordinal = ordinals[i];
        // 获取函数的RVA
        DWORD funcRva = functions[ordinal];

        // 显示导出函数的序号、名称和RVA
        printf("%-8d %-30s 0x%08X\n", ordinal + exportDir->Base, funcName, funcRva);
    }

    // 等待用户按下回车键后返回主菜单
    printf("\n按回车键返回主菜单...");
    getchar(); getchar();
}

void showImportInfo() {
    // 清屏，为显示导入表信息做准备
    system("cls");
    printf("========== 导入表信息 ==========\n");

    // 检查导入表是否存在
    // IMAGE_DIRECTORY_ENTRY_IMPORT 是导入表在数据目录中的索引
    if (g_tableAddress.size() <= IMAGE_DIRECTORY_ENTRY_IMPORT ||
        g_tableAddress[IMAGE_DIRECTORY_ENTRY_IMPORT].myVirtualAddress == 0) {
        printf("未找到导入表。\n");
        printf("\n按回车键返回主菜单...");
        getchar(); getchar(); // 等待用户按下回车键后返回主菜单
        return;
    }

    // 获取导入表的RVA（相对虚拟地址）
    DWORD importRva = g_tableAddress[IMAGE_DIRECTORY_ENTRY_IMPORT].myVirtualAddress;
    // 将RVA转换为FOA（文件偏移地址）
    DWORD importFoa = rvaToFoa(importRva);
    // 获取导入描述符结构的指针
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(g_peFileBuffer + importFoa);

    // 显示导入的DLL和函数
    printf("导入的DLL和函数:\n");
    printf("------------------------------------------------\n");

    // 遍历导入描述符
    while (importDesc->Name != 0) {
        // 获取DLL名称的FOA
        DWORD nameFoa = rvaToFoa(importDesc->Name);
        // 获取DLL名称的指针
        char* dllName = (char*)(g_peFileBuffer + nameFoa);
        printf("\nDLL: %s\n", dllName);

        // 获取导入函数的地址数组和IAT（导入地址表）的指针
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(g_peFileBuffer + rvaToFoa(importDesc->OriginalFirstThunk));
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(g_peFileBuffer + rvaToFoa(importDesc->FirstThunk));

        printf("%-8s %-30s %s\n", "序号", "函数", "IAT RVA");
        printf("------------------------------------------------\n");

        // 遍历导入函数
        while (thunk->u1.AddressOfData != 0) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // 如果设置了IMAGE_ORDINAL_FLAG，表示按序号导入
                printf("%-8d %-30s 0x%08X\n",
                       IMAGE_ORDINAL(thunk->u1.Ordinal), // 获取序号
                       "(按序号)", // 提示按序号导入
                       iat->u1.Function); // 显示IAT RVA
            } else {
                // 按名称导入
                // 获取导入函数名称的RVA，并转换为FOA
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(g_peFileBuffer + rvaToFoa(thunk->u1.AddressOfData));
                printf("%-8d %-30s 0x%08X\n",
                       importByName->Hint, // 提示号
                       importByName->Name, // 函数名称
                       iat->u1.Function); // 显示IAT RVA
            }

            // 移动到下一个导入函数
            thunk++;
            iat++;
        }

        // 移动到下一个导入描述符
        importDesc++;
    }

    // 等待用户按下回车键后返回主菜单
    printf("\n按回车键返回主菜单...");
    getchar(); getchar();
}

//显示文件中指定位置的原始二进制数据
void showRawData(DWORD offset, DWORD size) {
    system("cls");
    printf("========== 偏移量 0x%08X 处的原始数据 ==========\n", offset);
    printf("文件大小: %u 字节 (0x%X)\n", g_peFileSize, g_peFileSize);
    printf("请求范围: 0x%08X - 0x%08X\n", offset, offset + size - 1);

    if (offset >= g_peFileSize) {
        printf("错误: 偏移量(0x%X)超出文件范围(0x%X)。\n", offset, g_peFileSize);
        printf("\n按回车键返回主菜单...");
        getchar(); getchar();
        return;
    }

    if (size == 0) {
        printf("错误: 请求的大小不能为零。\n");
        printf("\n按回车键返回主菜单...");
        getchar(); getchar();
        return;
    }

    // 处理可能的整数溢出
    //或后面检查两个DWORD(32位无符号整数)相加是否发生溢出当计算结果超过32位最大值(0xFFFFFFFF) 时会发生"回绕"
    if ((offset + size) > g_peFileSize || (offset + size) < offset) {
        DWORD maxAvailable = g_peFileSize - offset;
        printf("错误: 请求的数据范围超出文件范围。\n");
        printf("可查看的最大大小: %u 字节 (0x%X)\n", maxAvailable, maxAvailable);
        printf("\n按回车键返回主菜单...");
        getchar(); getchar();
        return;
    }

    string hexData = formatHexData(g_peFileBuffer + offset, size);
    printf("%s\n", hexData.c_str());

    printf("\n按回车键返回主菜单...");
    getchar(); getchar();
}

//将二进制数据格式化为可读的十六进制文本
string formatHexData(const char* data, DWORD size) {
    //创建字符串流并设置输出格式
    stringstream ss;
    ss << hex << setfill('0');  //设置十六进制输出和填充字符'0'

    //遍历每个字节进行格式化
    for (DWORD i = 0; i < size; i++) {
        //将当前字节转换为2位十六进制数
        ss << setw(2) << (unsigned int)(unsigned char)data[i] << " ";
        //每16字节添加ASCII表示
        if ((i + 1) % 16 == 0) {
            ss << " | ";

            //输出当前16字节的ASCII表示
            for (DWORD j = i - 15; j <= i; j++) {
                char c = data[j];
                //可打印字符显示原字符，否则显示点号（ASCII 32-126可正常显示）
                ss << (isprint(c) ? c : '.');
            }
            //如果不是最后一行，添加换行
            if (i + 1 < size) ss << "\n";
        }
    }
    //处理不完整的最后一行
    DWORD remaining = size % 16;
    if (remaining != 0) {
        //补足16字节的空格
        for (DWORD i = remaining; i < 16; i++) {
            ss << "   ";
        }
        ss << " | ";
        for (DWORD j = size - remaining; j < size; j++) {
            char c = data[j];
            ss << (isprint(c) ? c : '.');
        }
    }
    //返回格式化后的字符串
    return ss.str();
}

//将内存地址(RVA)转换为文件偏移地址(FOA)
DWORD rvaToFoa(DWORD rva) {
    // 遍历所有节表项
    for (size_t i = 0; i < g_sectionTable.size(); i++) {
        DWORD va = g_sectionTable[i].myVirtualAddress;  // 节在内存中的起始RVA
        DWORD size = g_sectionTable[i].mySizeOfRawData; // 节在文件中的大小
        // 检查RVA是否在当前节范围内
        if (rva >= va && rva < va + size) {
            //文件中物理偏移 = 节的文件偏移 + (RVA - 节的虚拟地址)
            return g_sectionTable[i].myPointerToRawData + (rva - va);
        }
    }
    // 未找到对应节时直接返回RVA（适用于头部数据）
    return rva;
}

//安全释放程序使用的内存资源
void cleanup() {
    //检查全局文件缓冲区指针是否有效
    if (g_peFileBuffer != NULL) {
        //释放动态分配的内存
        delete[] g_peFileBuffer;
        //将指针设为NULL防止误用
        g_peFileBuffer = NULL;
    }
}
