/*
  Warnings:

  - You are about to drop the column `otp_ascii` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `otp_auth_url` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `otp_base32` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `otp_hex` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `otp_verified` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "otp_ascii",
DROP COLUMN "otp_auth_url",
DROP COLUMN "otp_base32",
DROP COLUMN "otp_hex",
DROP COLUMN "otp_verified",
ADD COLUMN     "otp_secret" TEXT;
