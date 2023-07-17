#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <tlhelp32.h>

using namespace std;
int main()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	bool processFound = 0;
	TCHAR VirusName[] = TEXT("mspaint.exe");
	/// Getting List of Running Processes 

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout << "CreateToolhelp32Snapshot (of processes) is failed\n";
		return 0;
	}
	/// Getting MS Paint Process ID

	/// Set the size of the pe32 structure before using it
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		cout << "Process32First is failed \n";
		// clean the snapshot object
		CloseHandle(hProcessSnap);
		return 0;
	}
	// Go through all the processes looking for mspaint.exe
	do
	{
		//print out the process name
		wcout << "Process name is " << pe32.szExeFile << "\n\n";
		if (_tcscmp(pe32.szExeFile, VirusName) == 0)
		{
			cout << "MS Paint process is found \n";
			processFound = 1;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	// Terminating MS Paint Process

	if (processFound)
	{
		/// get a handle on the process with intention to terminate it
		hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
		if (TerminateProcess(hProcess, 1))
			cout << "MS Paint process is successfully terminated \n";
		else
			cout << "FAIL to terminate MS Paint process \n";
	}
	else
		cout << "MS Paint process is not found\n";
	return 0;
}