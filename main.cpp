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
    DWORD myVirtualSize;         // 【修复新增】区段在内存中实际占用的大小
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
vector<SectionTable> g_sectionTable;    // 存储 PE 文件中所有区段 的数据
vector<TableAddress> g_tableAddress;    // 存储 PE 文件中所有数据目录表的位置和大小
BaseData g_baseData;                    // 存储 PE 文件的基础加载信息
char* g_peFileBuffer = NULL;            // 存储 PE 文件的原始二进制数据
DWORD g_peFileSize = 0;                 // 记录 PE 文件的大小
string g_filePath;                      // 存储 PE 文件的完整路径

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
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {                     
        printf("不是有效的PE文件（缺少DOS头）\n");
        exit(1);
    }

    // 检查NT头
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(g_peFileBuffer + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {        
        printf("不是有效的PE文件（缺少NT头）\n");
        exit(1);
    }

    // 确定是32位还是64位PE文件
    g_baseData.is64Bit = (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // 设置基本数据
    g_baseData.myImageBase = pNtHeader->OptionalHeader.ImageBase;               
    g_baseData.mySectionAlignment = pNtHeader->OptionalHeader.SectionAlignment; 
    g_baseData.myFileAlignment = pNtHeader->OptionalHeader.FileAlignment;      
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
        // 【修复新增】获取该区段在内存中的真实展开大小
        section.myVirtualSize = sectionHeader->Misc.VirtualSize; 
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
        printf("5. 按地址查看原始数据\n");
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
            int addrType;
            DWORD addr, size;
            printf("\n请选择地址类型 (1: 物理文件偏移FOA,  2: 内存虚拟地址RVA): ");
            scanf("%d", &addrType);
            printf("输入地址(十六进制): ");
            scanf("%x", &addr);
            printf("输入大小(十六进制): ");
            scanf("%x", &size);

            // 【修复】如果你选择了RVA，系统自动调用算法帮你转换为FOA再读取！
            DWORD offset = (addrType == 2) ? rvaToFoa(addr) : addr;
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
        
        DWORD size = min(g_sectionTable[i].mySizeOfRawData, static_cast<DWORD>(16));
        if (g_sectionTable[i].myPointerToRawData + size <= g_peFileSize) {
            string hexData = formatHexData(g_peFileBuffer + g_sectionTable[i].myPointerToRawData, size);
            printf("%s", hexData.c_str());
        }
        printf("\n");
    }

    printf("\n按回车键返回主菜单...");
    getchar(); 
    getchar();
}

void showExportInfo() {
    system("cls");
    printf("========== 导出表信息 ==========\n");

    if (g_tableAddress.size() <= IMAGE_DIRECTORY_ENTRY_EXPORT ||
        g_tableAddress[IMAGE_DIRECTORY_ENTRY_EXPORT].myVirtualAddress == 0) {
        printf("未找到导出表。\n");
        printf("\n按回车键返回主菜单...");
        getchar(); getchar(); 
        return;
    }

    DWORD exportRva = g_tableAddress[IMAGE_DIRECTORY_ENTRY_EXPORT].myVirtualAddress;
    DWORD exportFoa = rvaToFoa(exportRva);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(g_peFileBuffer + exportFoa);

    DWORD nameRva = exportDir->Name;
    DWORD nameFoa = rvaToFoa(nameRva);
    char* dllName = (char*)(g_peFileBuffer + nameFoa);

    printf("DLL名称: %s\n", dllName);
    printf("函数数量: %d\n", exportDir->NumberOfFunctions);
    printf("名称数量: %d\n", exportDir->NumberOfNames);
    printf("基址: %d\n", exportDir->Base);

    DWORD* functions = (DWORD*)(g_peFileBuffer + rvaToFoa(exportDir->AddressOfFunctions));
    DWORD* names = (DWORD*)(g_peFileBuffer + rvaToFoa(exportDir->AddressOfNames));
    WORD* ordinals = (WORD*)(g_peFileBuffer + rvaToFoa(exportDir->AddressOfNameOrdinals));

    printf("\n导出函数:\n");
    printf("%-8s %-30s %s\n", "序号", "名称", "RVA");
    printf("------------------------------------------------\n");

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        DWORD nameRva = names[i];
        DWORD nameFoa = rvaToFoa(nameRva);
        char* funcName = (char*)(g_peFileBuffer + nameFoa);
        WORD ordinal = ordinals[i];
        DWORD funcRva = functions[ordinal];

        printf("%-8d %-30s 0x%08X\n", ordinal + exportDir->Base, funcName, funcRva);
    }

    printf("\n按回车键返回主菜单...");
    getchar(); getchar();
}

void showImportInfo() {
    system("cls");
    printf("========== 导入表信息 ==========\n");

    if (g_tableAddress.size() <= IMAGE_DIRECTORY_ENTRY_IMPORT ||
        g_tableAddress[IMAGE_DIRECTORY_ENTRY_IMPORT].myVirtualAddress == 0) {
        printf("未找到导入表。\n");
        printf("\n按回车键返回主菜单...");
        getchar(); getchar();
        return;
    }

    DWORD importRva = g_tableAddress[IMAGE_DIRECTORY_ENTRY_IMPORT].myVirtualAddress;
    DWORD importFoa = rvaToFoa(importRva);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(g_peFileBuffer + importFoa);

    printf("导入的DLL和函数:\n");

    while (importDesc->Name != 0) {
        DWORD nameFoa = rvaToFoa(importDesc->Name);
        char* dllName = (char*)(g_peFileBuffer + nameFoa);
        printf("\n------------------------------------------------\n");
        printf("DLL: %s\n", dllName);
        printf("%-8s %-30s %s\n", "序号", "函数", "IAT RVA");
        printf("------------------------------------------------\n");

        // 兼容部分编译器 OriginalFirstThunk 为 0 的情况
        DWORD intRva = importDesc->OriginalFirstThunk != 0 ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        DWORD iatRva = importDesc->FirstThunk;

        // 【核心修复】动态判断 32/64 位架构，完美解决指针膨胀导致的内存错位
        if (g_baseData.is64Bit) {
            PIMAGE_THUNK_DATA64 thunk64 = (PIMAGE_THUNK_DATA64)(g_peFileBuffer + rvaToFoa(intRva));
            PIMAGE_THUNK_DATA64 iat64 = (PIMAGE_THUNK_DATA64)(g_peFileBuffer + rvaToFoa(iatRva));

            while (thunk64->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL64(thunk64->u1.Ordinal)) {
                    printf("%-8lld %-30s 0x%08llX\n", IMAGE_ORDINAL64(thunk64->u1.Ordinal), "(按序号)", iat64->u1.Function);
                } else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(g_peFileBuffer + rvaToFoa((DWORD)thunk64->u1.AddressOfData));
                    printf("%-8d %-30s 0x%08llX\n", importByName->Hint, importByName->Name, iat64->u1.Function);
                }
                thunk64++; iat64++;
            }
        } else {
            PIMAGE_THUNK_DATA32 thunk32 = (PIMAGE_THUNK_DATA32)(g_peFileBuffer + rvaToFoa(intRva));
            PIMAGE_THUNK_DATA32 iat32 = (PIMAGE_THUNK_DATA32)(g_peFileBuffer + rvaToFoa(iatRva));

            while (thunk32->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL32(thunk32->u1.Ordinal)) {
                    printf("%-8d %-30s 0x%08X\n", IMAGE_ORDINAL32(thunk32->u1.Ordinal), "(按序号)", iat32->u1.Function);
                } else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(g_peFileBuffer + rvaToFoa((DWORD)thunk32->u1.AddressOfData));
                    printf("%-8d %-30s 0x%08X\n", importByName->Hint, importByName->Name, iat32->u1.Function);
                }
                thunk32++; iat32++;
            }
        }
        importDesc++;
    }
    printf("\n按回车键返回主菜单...");
    getchar(); getchar();
}

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

string formatHexData(const char* data, DWORD size) {
    stringstream ss;
    ss << hex << setfill('0'); 

    for (DWORD i = 0; i < size; i++) {
        ss << setw(2) << (unsigned int)(unsigned char)data[i] << " ";
        if ((i + 1) % 16 == 0) {
            ss << " | ";
            for (DWORD j = i - 15; j <= i; j++) {
                char c = data[j];
                ss << (isprint(c) ? c : '.');
            }
            if (i + 1 < size) ss << "\n";
        }
    }
    DWORD remaining = size % 16;
    if (remaining != 0) {
        for (DWORD i = remaining; i < 16; i++) {
            ss << "   ";
        }
        ss << " | ";
        for (DWORD j = size - remaining; j < size; j++) {
            char c = data[j];
            ss << (isprint(c) ? c : '.');
        }
    }
    return ss.str();
}

//将内存地址(RVA)转换为文件偏移地址(FOA)
DWORD rvaToFoa(DWORD rva) {
    for (size_t i = 0; i < g_sectionTable.size(); i++) {
        DWORD va = g_sectionTable[i].myVirtualAddress;  
        // 【修复逻辑】内存边界判断必须使用 VirtualSize
        DWORD vSize = g_sectionTable[i].myVirtualSize;
        if (vSize == 0) vSize = g_sectionTable[i].mySizeOfRawData; // 兼容部分畸形PE

        if (rva >= va && rva < va + vSize) {
            return g_sectionTable[i].myPointerToRawData + (rva - va);
        }
    }
    return rva;
}

void cleanup() {
    if (g_peFileBuffer != NULL) {
        delete[] g_peFileBuffer;
        g_peFileBuffer = NULL;
    }
}
