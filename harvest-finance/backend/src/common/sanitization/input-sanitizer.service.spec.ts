import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { InputSanitizerService } from './input-sanitizer.service';

describe('InputSanitizerService', () => {
  let service: InputSanitizerService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [InputSanitizerService],
    }).compile();

    service = module.get<InputSanitizerService>(InputSanitizerService);
  });

  describe('validateStellarPublicKey', () => {
    const validKey = 'GA5W327WXCSFDZ565USTKA6H6Z6IM7S73KQXYYV667F55VEF75BGF22N';

    it('should return the trimmed key when a valid G-address is provided', () => {
      expect(service.validateStellarPublicKey(validKey)).toBe(validKey);
      expect(service.validateStellarPublicKey(`   ${validKey}   \n`)).toBe(validKey);
    });

    it('should throw BadRequestException if key is null, undefined, or not a string', () => {
      expect(() => service.validateStellarPublicKey(null as any)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey(undefined as any)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey(12345 as any)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey({} as any)).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for non-G prefixes', () => {
      const sKey = 'SA5W327WXCSFDZ565USTKA6H6Z6IM7S73KQXYYV667F55VEF75BGF22N';
      const mKey = 'MA5W327WXCSFDZ565USTKA6H6Z6IM7S73KQXYYV667F55VEF75BGF22N';
      expect(() => service.validateStellarPublicKey(sKey)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey(mKey)).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for truncated or extended keys', () => {
      const truncated = validKey.slice(0, 55);
      const extended = validKey + 'A';
      expect(() => service.validateStellarPublicKey(truncated)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey(extended)).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for keys containing invalid base32 characters (0, 1, 8, 9)', () => {
      const withZero = validKey.slice(0, 55) + '0';
      const withOne = validKey.slice(0, 55) + '1';
      const withEight = validKey.slice(0, 55) + '8';
      const withNine = validKey.slice(0, 55) + '9';
      expect(() => service.validateStellarPublicKey(withZero)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey(withOne)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey(withEight)).toThrow(BadRequestException);
      expect(() => service.validateStellarPublicKey(withNine)).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for keys with lowercase alphabet letters', () => {
      const lowercaseKey = validKey.toLowerCase();
      expect(() => service.validateStellarPublicKey(lowercaseKey)).toThrow(BadRequestException);
    });
  });

  describe('validateUUID', () => {
    const validV4UUID = '123e4567-e89b-12d3-a456-426614174000';

    it('should return a lowercase UUID when a valid UUID format is provided', () => {
      expect(service.validateUUID(validV4UUID)).toBe(validV4UUID);
      expect(service.validateUUID('123E4567-E89B-12D3-A456-426614174000')).toBe(validV4UUID);
    });

    it('should return a trimmed lowercase UUID', () => {
      expect(service.validateUUID(`   ${validV4UUID}   `)).toBe(validV4UUID);
    });

    it('should throw BadRequestException if UUID is null, undefined, or not a string', () => {
      expect(() => service.validateUUID(null as any)).toThrow(BadRequestException);
      expect(() => service.validateUUID(undefined as any)).toThrow(BadRequestException);
      expect(() => service.validateUUID(987654321 as any)).toThrow(BadRequestException);
      expect(() => service.validateUUID([] as any)).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for empty or whitespace-only strings', () => {
      expect(() => service.validateUUID('')).toThrow(BadRequestException);
      expect(() => service.validateUUID('   ')).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for malformed formats (e.g., missing hyphens)', () => {
      const missingHyphens = '123e4567e89b12d3a456426614174000';
      expect(() => service.validateUUID(missingHyphens)).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for invalid characters (non-hex characters)', () => {
      const invalidChars = '123e4567-e89b-12d3-a456-42661417400g'; // contains 'g'
      expect(() => service.validateUUID(invalidChars)).toThrow(BadRequestException);
    });

    it('should throw BadRequestException for incorrect lengths', () => {
      const tooShort = '123e4567-e89b-12d3-a456-42661417400';
      const tooLong = '123e4567-e89b-12d3-a456-4266141740000';
      expect(() => service.validateUUID(tooShort)).toThrow(BadRequestException);
      expect(() => service.validateUUID(tooLong)).toThrow(BadRequestException);
    });
  });
});
