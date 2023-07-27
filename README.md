# project-9
AES  software implementation
# 实现方式
### 1.格式处理
AES 的处理单位是字节，128 位的输入明文分组 P 和输入密钥 K 都被分成 16个字节，分别记为 P = P0 P1 …P15 和 K = K0 K1 …K15。如，明文分组为 P =
abcdefghijklmnop, 其中的字符 a 对应 P0，p 对应 P15。其实我们将明文转化为 ascll 码
表示为一个字节。一般地，明文分组用字节为单位的正方形矩阵描述，称为状态矩阵。
在算法的每一轮中，状态矩阵的内容不断发生变化，最后的结果作为密文输出。该矩阵
中字节的排列顺序为从上到下、从左至右依次排列，如下图所示：
![图片1](https://github.com/jlwdfq/project-9/assets/129512207/9c8c7ed2-f137-4353-bc3a-4b08b48923d7)

类似地，128 位密钥也是用字节为单位的 4×4 大小矩阵表示，所以矩阵的每一列被
称为 1 个 32 位比特字。通过密钥编排函数将该密钥矩阵被扩展成一个 44 个字组成的
序列 W[0],W[1], …,W[43], 该序列的前 4 个元素 W[0],W[1],W[2],W[3] 是原始密钥，用
于加密运算中的初始密钥加（下面介绍）; 后面 40 个字分为 10 组，每组 4 个字（128
比特）分别用于 10 轮加密运算中的轮密钥加，如下图所示：
![图片2](https://github.com/jlwdfq/project-9/assets/129512207/67365512-61fb-4dce-ba84-88d603ed1627)
### 2.轮密钥扩展
每轮加密的密钥都是由与原始密钥变化而来的，第i轮加密需要用的密钥序列为W[4i]、W[4i+1]、W[4i+2]、W[4i+3]，这时我们就需要跟据加密轮数随时扩展我们的轮密钥。

已知原始密钥W[0],W[1]W[2],W[3]，后续密钥通过递归函数得到：
![G$~P1Y7201RKMD3GZ)L}`7H](https://github.com/jlwdfq/project-9/assets/129512207/67cbcf50-7266-4eb1-8414-b9b921f4743f)

```c
int keyExpansion(const uint8_t* key, uint32_t keyLen, AesKey* aesKey) {

    if (NULL == key || NULL == aesKey) {
        printf("keyExpansion param is NULL\n");
        return -1;
    }

    if (keyLen != 16) {
        printf("keyExpansion keyLen = %d, Not support.\n", keyLen);
        return -1;
    }

    uint32_t* w = aesKey->eK;
    uint32_t* v = aesKey->dK;

    /* keyLen is 16 Bytes, generate uint32_t W[44]. */

    /* W[0-3] */
    for (int i = 0; i < 4; ++i) {
        LOAD32H(w[i], key + 4 * i);
    }

    /* W[4-43] */
    for (int i = 0; i < 10; ++i) {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }

    w = aesKey->eK + 44 - 4;
    for (int j = 0; j < 11; ++j) {

        for (int i = 0; i < 4; ++i) {
            v[i] = w[i];
        }
        w -= 4;
        v += 4;
    }

    return 0;
}

```
### 3.字节代换
AES 的字节代换其实就是查表代换，分别定义一个 s 盒与逆 s 盒以供加解密使用。
先将明文做成一个 4×4 的明文矩阵，每个明文由 ascll 码转为一个字节，实现分组长为
128bit 每组的加密。然后将该字节转换为两位 16 进制数表示，根据高位为行值，低位
作为列值，取出 S 盒或者逆 S 盒中对应的元素作为输出，就实现了字节代换。（s 盒或
者说代换表是已经预设好的，不需要加命者自行设计）。在预处理阶段我们先在代码中
给出预设 s 盒与逆 s 盒的数据，再进行字节处理。
### 4.行位移
行移位是一个简单的左循环移位操作。当密钥长度为 128 比特时，状态矩阵的第 0
行左移 0 字节，第 1 行左移 1 字节，第 2 行左移 2 字节，第 3 行左移 3 字节，同理行移
位的逆变换也就是将状态矩阵中的每一行执行相反的移位操作，即状态矩阵的第 0 行右
移 0 字节，第 1 行右移 1 字节，第 2 行右移 2 字节，第 3 行右移 3 字节。如下图所示：
![图片3](https://github.com/jlwdfq/project-9/assets/129512207/775aaf40-a0fa-4958-867c-97304ca8b078)
```c
int shiftRows(uint8_t(*state)[4]) {
    uint32_t block[4] = { 0 };

    /* i: row */
    for (int i = 0; i < 4; ++i) {
        LOAD32H(block[i], state[i]);
        block[i] = ROF32(block[i], 8 * i);
        STORE32H(block[i], state[i]);
    }

    return 0;
}

int invShiftRows(uint8_t(*state)[4]) {
    uint32_t block[4] = { 0 };

    /* i: row */
    for (int i = 0; i < 4; ++i) {
        LOAD32H(block[i], state[i]);
        block[i] = ROR32(block[i], 8 * i);
        STORE32H(block[i], state[i]);
    }

    return 0;
}
```
### 5.列混合
为了实现加密算法的混淆扩散特性，提高安全性，列混合通过矩阵相乘来实现的，
经行移位后的状态矩阵与固定的矩阵相乘，得到混淆后的状态矩阵，如下图的公式所示：
![图片4](https://github.com/jlwdfq/project-9/assets/129512207/a173b58e-e577-4b5c-986a-d066eb8a1fd7)
```c
int mixColumns(uint8_t(*state)[4]) {
    uint8_t tmp[4][4];
    uint8_t M[4][4] = { {0x02, 0x03, 0x01, 0x01},
                       {0x01, 0x02, 0x03, 0x01},
                       {0x01, 0x01, 0x02, 0x03},
                       {0x03, 0x01, 0x01, 0x02} };

    /* copy state[4][4] to tmp[4][4] */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            tmp[i][j] = state[i][j];
        }
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = GMul(M[i][0], tmp[0][j]) ^ GMul(M[i][1], tmp[1][j])
                ^ GMul(M[i][2], tmp[2][j]) ^ GMul(M[i][3], tmp[3][j]);
        }
    }

    return 0;
}

```
### 6.轮密钥异或
就是将 128 位轮密钥 W[4i]、W[4i+1]、W[4i+2]、W[4i+3] 与同状态矩阵中的数据
进行逐位异或操作得到，经过字节代换、行位移、列混合的一组 4×4 明文矩阵称为本轮
的状态矩阵。
```c
int addRoundKey(uint8_t(*state)[4], const uint32_t* key) {
    uint8_t k[4][4];

    /* i: row, j: col */
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            k[i][j] = (uint8_t)BYTE(key[j], 3 - i);  /* copy uint32 key[4] to uint8 k[4][4] */
            state[i][j] ^= k[i][j];
        }
    }

    return 0;
}
```
# 实验结果
![image](https://github.com/jlwdfq/project-9/assets/129512207/d703af21-799d-4232-9e9e-d21c4fb2f990)
# 实验环境
| 语言  | 系统      | 平台   | 处理器                     |
|-------|-----------|--------|----------------------------|
| Cpp   | Windows10 | vs2022 | Intel(R) Core(TM)i7-11800H |
# 小组分工
戴方奇 202100460092 单人组完成project9
