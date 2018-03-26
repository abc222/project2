/*
 * Segmentation-based user mode implementation
 * Copyright (c) 2001,2003 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.23 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/ktypes.h>
#include <geekos/kassert.h>
#include <geekos/defs.h>
#include <geekos/mem.h>
#include <geekos/string.h>
#include <geekos/malloc.h>
#include <geekos/int.h>
#include <geekos/gdt.h>
#include <geekos/segment.h>
#include <geekos/tss.h>
#include <geekos/kthread.h>
#include <geekos/argblock.h>
#include <geekos/user.h>

#include <geekos/debug.h>
/* ----------------------------------------------------------------------
 * Variables
 * ---------------------------------------------------------------------- */

#define DEFAULT_USER_STACK_SIZE 8192


/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */


/*
 * Create a new user context of given size
 */

/* TODO: Implement
static struct User_Context* Create_User_Context(ulong_t size)
*/
/**需在此文件各函数前增加一个函数，此函数的功能是按给定的大小创建一个用户级进程上下文，具体实现如下：  
函数功能:按给定的大小创建一个用户级进程上下文**/
static struct User_Context* old_Create_User_Context(ulong_t size)
{
 	struct User_Context *userContext;
 	size = Round_Up_To_Page(size);
 	userContext = (struct User_Context *)Malloc(sizeof(struct User_Context));
 	/* 内存分配成功则继续为 userContext 下的 memory 分配内存空间 */
 	//为用户态进程     
	if (userContext != 0)         
		userContext->memory = Malloc(size);     
	//为核心态进程     
	else         
		goto fail;     
	//内存为空      
	if (userContext->memory == 0)        
		goto fail;  
 	memset(userContext->memory, '\0', size);
 	userContext->size = size;

	//以下为用户态进程创建LDT(段描述符表)     
	//新建一个LDT描述符
 	userContext->ldtDescriptor = Allocate_Segment_Descriptor();
 	if (userContext->ldtDescriptor == 0)
	 	goto fail;
 	
	//初始化段描述符
 	Init_LDT_Descriptor(userContext->ldtDescriptor, userContext->ldt,
NUM_USER_LDT_ENTRIES);
 	//新建一个 LDT 选择子 
 	userContext->ldtSelector = Selector(KERNEL_PRIVILEGE, true,
Get_Descriptor_Index(userContext->ldtDescriptor));
	//新建一个代码段描述符 
 	Init_Code_Segment_Descriptor(&userContext->ldt[0],
(ulong_t)userContext->memory, size / PAGE_SIZE, USER_PRIVILEGE);
	//新建一个数据段描述符
 	Init_Data_Segment_Descriptor(&userContext->ldt[1],
(ulong_t)userContext->memory, size / PAGE_SIZE, USER_PRIVILEGE);
 	//新建数据段和代码段选择子
 	userContext->csSelector = Selector(USER_PRIVILEGE, false, 0);
 	userContext->dsSelector = Selector(USER_PRIVILEGE, false, 1);
 	//将引用数清零 
 	userContext->refCount = 0;
 	return userContext;
fail:      
	if (userContext != 0){         
		if (userContext->memory != 0){            
			Free(userContext->memory);        
		}         
		Free(userContext);     
	}      
	return 0; 
}

/*new*/
static struct User_Context* Create_User_Context(ulong_t size) 
{     
	struct User_Context *userContext;
	size = Round_Up_To_Page(size);     
	userContext = (struct User_Context *)Malloc(sizeof(struct User_Context));
	/* 内存分配成功则继续为 userContext 下的 memory 分配内存空间 */
	if (userContext == NULL)     
	{
	     if (userSegDebug) Print("Error! Out of Memory Space\n");
	     return NULL;
	}     
	userContext->memory = (char *)Malloc(size);     
	if (userContext->memory == NULL)
	{         
		 if (userSegDebug) Print("Error! Out of Memory Space\n");
		 Free(userContext);         
		 return NULL;
	}     
	memset(userContext->memory, '\0', size);
	userContext->size = size; 
 
    /* 新建一个 LDT 描述符 */     
    userContext->ldtDescriptor = Allocate_Segment_Descriptor();     
    if (userContext->ldtDescriptor == NULL)
    {         
	     if (userSegDebug)
	         Print("Error! Failed to Allocate Segment Descriptor\n");         
	     Free(userContext->memory);         
		 return NULL;     
	}     
	/* 初始化段描述符 */
	Init_LDT_Descriptor(userContext->ldtDescriptor, userContext->ldt, NUM_USER_LDT_ENTRIES);     
	/* 新建一个 LDT 选择子 */
	userContext->ldtSelector = Selector(KERNEL_PRIVILEGE, true, Get_Descriptor_Index(userContext->ldtDescriptor));     
	/* 新建一个代码段描述符 */     
	Init_Code_Segment_Descriptor(&userContext->ldt[0], (ulong_t)userContext->memory, size / PAGE_SIZE, USER_PRIVILEGE);
	/* 新建一个数据段描述符 */     
	Init_Data_Segment_Descriptor(&userContext->ldt[1], (ulong_t)userContext->memory, size / PAGE_SIZE, USER_PRIVILEGE);     
	/* 新建数据段和代码段选择子 */
	userContext->csSelector = Selector(USER_PRIVILEGE, false, 0); 
	userContext->dsSelector = Selector(USER_PRIVILEGE, false, 1);
	/* 将引用数清零 */     
	userContext->refCount = 0; 
 
	 if (userSegDebug)     
	 {       
		  Print(" virtSpace    = %lx\n", (ulong_t)userContext->memory);       
		  Print(" virtSize     = %lx\n", (ulong_t)size / PAGE_SIZE);       
		  Print(" codeSelector = %x\n", userContext->csSelector);       
		  Print(" dataSelector = %x\n", userContext->dsSelector);     
	 } 
	 return userContext; 
} 


static bool Validate_User_Memory(struct User_Context* userContext,
    ulong_t userAddr, ulong_t bufSize)
{
    ulong_t avail;

    if (userAddr >= userContext->size)
        return false;

    avail = userContext->size - userAddr;
    if (bufSize > avail)
        return false;

    return true;
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
void old_Destroy_User_Context(struct User_Context* userContext)
{
    /*
     * Hints:
     * - you need to free the memory allocated for the user process
     * - don't forget to free the segment descriptor allocated
     *   for the process's LDT
     */
    //TODO("Destroy a User_Context");
 	//释放 LDT descriptor
 	Free_Segment_Descriptor(userContext->ldtDescriptor);
	userContext->ldtDescriptor=0; 
 	Free(userContext->memory);//释放内存空间 
	userContext->memory=0;
 	Free(userContext);//释放userContext本身占用的内存
	userContext=0;
}

/*new*/
void Destroy_User_Context(struct User_Context* userContext) 
{     
	KASSERT(userContext->refCount == 0);     
	/* 释放 LDT descriptor */     
	Free_Segment_Descriptor(userContext->ldtDescriptor);     
	/* 释放内存空间 */     
	Disable_Interrupts();     
	Free(userContext->memory);     
	Free(userContext);     
	Enable_Interrupts(); 
} 

/*
 * Load a user executable into memory by creating a User_Context
 * data structure.
 * Params:
 * exeFileData - a buffer containing the executable to load
 * exeFileLength - number of bytes in exeFileData
 * exeFormat - parsed ELF segment information describing how to
 *   load the executable's text and data segments, and the
 *   code entry point address
 * command - string containing the complete command to be executed:
 *   this should be used to create the argument block for the
 *   process
 * pUserContext - reference to the pointer where the User_Context
 *   should be stored
 *
 * Returns:
 *   0 if successful, or an error code (< 0) if unsuccessful
 */
int old_Load_User_Program(char *exeFileData, ulong_t exeFileLength,
	struct Exe_Format *exeFormat,const char *command,
	struct User_Context **pUserContext)
{
    /*
     * Hints:
     * - Determine where in memory each executable segment will be placed
     * - Determine size of argument block and where it memory it will
     *   be placed
     * - Copy each executable segment into memory
     * - Format argument block in memory
     * - In the created User_Context object, set code entry point
     *   address, argument block address, and initial kernel stack pointer
     *   address
     */
    //TODO("Load a user executable into a user memory space using segmentation");
	unsigned int i;
 	struct User_Context *userContext = 0;
 	ulong_t maxva = 0;//要分配的最大内存空间
	unsigned int numArgs;//进程数目 
	ulong_t argBlockSize;//参数块的大小  
	ulong_t size,argBlockAddr;//参数块地址
 	/* 计算用户态进程所需的最大内存空间 */
 	for (i = 0; i < exeFormat->numSegments; i++)
 	{
 		struct Exe_Segment *segment = &exeFormat->segmentList[i];
 		ulong_t topva = segment->startAddress + segment->sizeInMemory;
 		if (topva > maxva) maxva = topva;
 	}
 	/* 获取参数块的大小 */
 	Get_Argument_Block_Size(command, &numArgs, &argBlockSize);
 	/* 用户进程大小 = 参数块总大小 + 进程堆栈大小(8192) */
	size = Round_Up_To_Page(maxva) + DEFAULT_USER_STACK_SIZE;
 	/* 参数块地址 */
 	argBlockAddr = size;
 	size += argBlockSize;
 	/* 按相应大小创建一个进程 */
 	userContext = Create_User_Context(size);
 	/* 如果是核心态进程 */
 	if (userContext == NULL)
 		return -1;
 	/* 将用户程序中的各段内容复制到分配的用户内存空间 */
 	for (i = 0; i < exeFormat->numSegments; i++)
 	{
 		struct Exe_Segment *segment = &exeFormat->segmentList[i];
		//根据段信息将用户程序中的各段内容复制到分配的用户内存空间
 		memcpy(userContext->memory + segment->startAddress,
exeFileData + segment->offsetInFile,segment->lengthInFile);
 	}
 	/* 格式化参数块 */
 	Format_Argument_Block(userContext->memory + argBlockAddr, numArgs,
argBlockAddr, command);
 	/* 初始化数据段、堆栈段及代码段信息 */
 	userContext->entryAddr = exeFormat->entryAddr;
 	userContext->argBlockAddr = argBlockAddr;
 	userContext->stackPointerAddr = argBlockAddr;
 	/* 将初始化完毕的 User_Context 赋给*pUserContext */
 	*pUserContext = userContext;
 	return 0;

}

/*new*/
int Load_User_Program(char *exeFileData, ulong_t exeFileLength,     
struct Exe_Format *exeFormat, const char *command,     
struct User_Context **pUserContext) 
{     
	unsigned int i;     
	struct User_Context *userContext = NULL; 
 
    /* 要分配的最大内存空间 */     
    ulong_t maxva = 0;     
    /* 计算用户态进程所需的最大内存空间 */     
    for (i = 0; i < exeFormat->numSegments; i++)     
    {         
	    struct Exe_Segment *segment = &exeFormat->segmentList[i];        
	    ulong_t topva = segment->startAddress + segment->sizeInMemory;        
	    if (topva > maxva) maxva = topva; 
	} 
    /* 程序参数数目 */     
    unsigned int numArgs;     
    /* 获取参数块的大小 */     
    ulong_t argBlockSize;     
    Get_Argument_Block_Size(command, &numArgs, &argBlockSize);     
    /* 用户进程大小 = 参数块总大小 + 进程堆栈大小(8192) */     
    ulong_t size = Round_Up_To_Page(maxva) + DEFAULT_USER_STACK_SIZE;     
    /* 参数块地址 */     
    ulong_t argBlockAddr = size;     
    size += argBlockSize;     
    /* 按相应大小创建一个进程 */     
    userContext = Create_User_Context(size);     
    /* 如果进程创建失败则返回错误信息 */     
    if (userContext == NULL)     
    {         
	    if (userSegDebug)             
		    Print("Error! Failed to Create User Context\n");         
	    return -1;     
	} 
 
    /* 将用户程序中的各段内容复制到分配的用户内存空间 */     
    for (i = 0; i < exeFormat->numSegments; i++)     
    {        
	    struct Exe_Segment *segment = &exeFormat->segmentList[i];        
	    memcpy(userContext->memory + segment->startAddress,                
			    exeFileData + segment->offsetInFile,                
			    segment->lengthInFile);    
	} 
 
    /* 格式化参数块 */     
    Format_Argument_Block(userContext->memory + argBlockAddr, numArgs, argBlockAddr, command);     
    /* 初始化数据段、堆栈段及代码段信息 */     
    userContext->entryAddr = exeFormat->entryAddr;     
    userContext->argBlockAddr = argBlockAddr;     
    userContext->stackPointerAddr = argBlockAddr; 
 
    /* 将初始化完毕的 User_Context 赋给*pUserContext */     
    *pUserContext = userContext; 
 
    return 0; 
} 



/*
 * Copy data from user memory into a kernel buffer.
 * Params:
 * destInKernel - address of kernel buffer
 * srcInUser - address of user buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool old_Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t bufSize)
{
    /*
     * Hints:
     * - the User_Context of the current process can be found
     *   from g_currentThread->userContext
     * - the user address is an index relative to the chunk
     *   of memory you allocated for it
     * - make sure the user buffer lies entirely in memory belonging
     *   to the process
     */
    //TODO("Copy memory from user buffer to kernel buffer");
    //Validate_User_Memory(NULL,0,0); /* delete this; keeps gcc happy */

	struct User_Context* userContext = g_currentThread->userContext;
 	/* 如果访问的用户内存空间非法(越界访问)，则直接返回失败 */
 	if (!Validate_User_Memory(userContext, srcInUser, bufSize))
 		return false;
 	/*拷贝当前用户内存空间数据到系统内核空间 */
 	memcpy(destInKernel, userContext->memory + srcInUser, bufSize);
 	return true;
}

/*new*/
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t bufSize) 
{     
	struct User_Context* userContext = g_currentThread->userContext;     
	/* 如果访问的用户内存空间非法(越界访问)，则直接返回失败 */     
	if (!Validate_User_Memory(userContext, srcInUser, bufSize))         
		return false;     
	/* 拷贝当前用户内存空间数据到系统内核空间 */     
	memcpy(destInKernel, userContext->memory + srcInUser, bufSize);     
	/* 拷贝成功则返回 1 */     
	return true; 
} 

/*
 * Copy data from kernel memory into a user buffer.
 * Params:
 * destInUser - address of user buffer
 * srcInKernel - address of kernel buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool old_Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t bufSize)
{
    /*
     * Hints: same as for Copy_From_User()
     */
    //TODO("Copy memory from kernel buffer to user buffer");

	struct User_Context* userContext = g_currentThread->userContext;
 	/* 如果需要拷贝的内容超出用户内存空间(越界)，则直接返回失败 */
 	if (!Validate_User_Memory(userContext, destInUser, bufSize))
 		return false;
 	/* 拷贝当前系统内核空间数据到用户内存空间 */
 	memcpy(userContext->memory + destInUser, srcInKernel, bufSize);
 	return true;
}
/*new*/
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t bufSize) 
{     
	struct User_Context* userContext = g_currentThread->userContext;     
	/* 如果需要拷贝的内容超出用户内存空间(越界)，则直接返回失败 */     
	if (!Validate_User_Memory(userContext, destInUser, bufSize))         
		return false;     
	/* 拷贝当前系统内核空间数据到用户内存空间 */     
	memcpy(userContext->memory + destInUser, srcInKernel, bufSize);     
	/* 拷贝成功则返回 1 */     
	return true; 
}

/*
 * Switch to user address space belonging to given
 * User_Context object.
 * Params:
 * userContext - the User_Context
 */
void old_Switch_To_Address_Space(struct User_Context *userContext)
{
    /*
     * Hint: you will need to use the lldt assembly language instruction
     * to load the process's LDT by specifying its LDT selector.
     */
    //TODO("Switch to user address space using segmentation/LDT");

	/* 切换到新的局部描述符表(LDT) */
 	ushort_t ldtSelector = userContext->ldtSelector;
 	__asm__ __volatile__ ("lldt %0"::"a" (ldtSelector));
}
/*new*/
void Switch_To_Address_Space(struct User_Context *userContext) 
{     
	/* 切换到新的局部描述符表(LDT) */     
	ushort_t ldtSelector = userContext->ldtSelector;     
	__asm__ __volatile__ (     
	"lldt %0"     
	:     
	: "a" (ldtSelector)     
	); 
}

