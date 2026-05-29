-- CreateEnum
CREATE TYPE "PaymentKind" AS ENUM ('PAID', 'FREE_TRIAL', 'FREE_PRICING');

-- CreateEnum
CREATE TYPE "PaymentStatus" AS ENUM ('PENDING', 'SETTLED', 'REFUND_PENDING', 'REFUNDED', 'FAILED');

-- CreateTable
CREATE TABLE "Payment" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "kind" "PaymentKind" NOT NULL,
    "status" "PaymentStatus" NOT NULL DEFAULT 'PENDING',
    "walletAddress" TEXT,
    "network" TEXT,
    "asset" TEXT,
    "amountAtomic" TEXT,
    "payTo" TEXT,
    "nonce" TEXT,
    "scheme" TEXT,
    "x402Version" INTEGER,
    "settleTxHash" TEXT,
    "refundTxHash" TEXT,
    "rawPayload" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "settledAt" TIMESTAMP(3),
    "refundedAt" TIMESTAMP(3),

    CONSTRAINT "Payment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Payment_scanId_key" ON "Payment"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "Payment_settleTxHash_key" ON "Payment"("settleTxHash");

-- CreateIndex
CREATE INDEX "Payment_userId_idx" ON "Payment"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "Payment_network_nonce_key" ON "Payment"("network", "nonce");

-- AddForeignKey
ALTER TABLE "Payment" ADD CONSTRAINT "Payment_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Payment" ADD CONSTRAINT "Payment_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
