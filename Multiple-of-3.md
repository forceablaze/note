title: "Multiple of 3"
date: 2015-04-29 23:40:29
tags: C
---
利用位數累加的方式，可以推算出 mod 值。

0xABCD mod 3 = (A * 0xFFF ＋ B * 0xFF + C * 0xF) mod 3
	= (A + B + C) mod 3

最後計算出餘數再直接判斷。
``` c
int is_mod3(__u32 x)
{
	unsigned int result;

	result = (x & 0xf) +
		((x & 0xf0) >> 4) +
		((x & 0xf00) >> 8) +
		((x & 0xf000) >> 12) +
		((x & 0xf0000) >> 16) +
		((x & 0xf00000) >> 20) +
		((x & 0xf000000) >> 24) +
		((x & 0xf0000000) >> 28);

	while(result > 0xf) {
		result = (result & 0xf) +
			((result & 0xf0) >> 4);
	}

	switch(result) {
	case 3:
	case 6:
	case 9:
	case 12:
	case 15:
		return 1;
	default:
		return 0;
	}
}
```
