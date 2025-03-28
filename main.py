import re
import sqlite3
from datetime import datetime, timezone
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from typing import Optional
from astrbot.api.all import *

class CipherServer:
    def __init__(self, db_path='./data/cipher.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cipher_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    mode TEXT CHECK(mode IN ('encrypt', 'decrypt')),
                    content TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    def _log_operation(self, user_id: str, mode: str, content: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO cipher_logs (user_id, mode, content) VALUES (?, ?, ?)',
                (user_id, mode, content)
            )

    def encrypt_text(self, text: str) -> str:
        # 将文本编码为UTF-8字节
        bytes_data = text.encode('utf-8')
        # 将每个字节转换为8位二进制字符串
        binary = ''.join([bin(byte)[2:].zfill(8) for byte in bytes_data])
        return ''.join([self.BINARY_MAP.get(binary[i:i+2], '我') for i in range(0, len(binary), 2)])

    def decrypt_text(self, cipher: str) -> str:
        binary = []
        for char in cipher:
            if (bits := self.TEXT_MAP.get(char)) is None:
                raise ValueError("包含无效字符")
            binary.append(bits)
        binary_str = ''.join(binary)
        if len(binary_str) % 8 != 0:
            raise ValueError("无效的密文长度")
        bytes_list = []
        for i in range(0, len(binary_str), 8):
            byte_str = binary_str[i:i+8]
            bytes_list.append(int(byte_str, 2))
        try:
            return bytes(bytes_list).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("解密失败：无效的字节序列")

    BINARY_MAP = {'00': '我', '01': '要', '10': '吃', '11': '饭'}
    TEXT_MAP = {v: k for k, v in BINARY_MAP.items()}

@register("cipher", "Yuki Soffd", "基于'我要吃饭'的二进制加解密插件", "1.0.0", "https://github.com/Soffd/encrypt-and-decrypt")
class CipherPlugin(Star):
    server = CipherServer()
    
    def __init__(self, context: Context):
        super().__init__(context)
    
    @filter.command("加密")
    async def encrypt_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：加密 明文内容")
            return
        
        user_id = event.get_sender_id()
        try:
            cipher = self.server.encrypt_text(args[1])
            self.server._log_operation(user_id, 'encrypt', args[1])
            yield event.plain_result(f"🔒 加密结果：\n{cipher}")
        except Exception as e:
            logger.error(f"加密失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 加密失败，请检查输入内容")

    @filter.command("解密")
    async def decrypt_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：解密 密文内容")
            return
        
        user_id = event.get_sender_id()
        try:
            plaintext_result = self.server.decrypt_text(args[1])
            self.server._log_operation(user_id, 'decrypt', args[1])
            yield event.plain_result(f"🔓 解密结果：\n{plaintext_result}")
        except ValueError as e:
            yield event.plain_result(f"❌ 解密失败：{str(e)}")
        except Exception as e:
            logger.error(f"解密失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 解密失败，请检查密文格式")

    @filter.command("我要吃饭")
    async def help_command(self, event: AstrMessageEvent):
        help_text = (
            "📖 加密插件使用说明\n"
            "——基于「我要吃饭」的二进制加解密——\n\n"
            "🔹 作者：Yuki Soffd\n"
            "🔹 版本：1.0.0\n\n"
            "📌 使用指令：\n"
            "1. 加密 <明文> - 将文字转为密文\n"
            "  例：加密 你好\n\n"
            "2. 解密 <密文> - 将密文还原为文字\n"
            "  例：解密 我吃要饭\n\n"
            "⚠️ 注意：密文只能包含「我」「要」「吃」「饭」四个字符"
        )
        yield event.plain_result(help_text)
