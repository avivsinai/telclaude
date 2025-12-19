/**
 * Image optimization using sharp.
 * Resizes and compresses images to reduce token costs and upload size.
 * Adopted from clawdis approach.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import sharp from "sharp";

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "media-optimize" });

/**
 * Image optimization options.
 */
export type ImageOptimizeOptions = {
	/** Maximum dimension (width or height) in pixels. Default: 2048 */
	maxDimension?: number;
	/** Target max file size in bytes. Default: 5MB */
	maxSizeBytes?: number;
	/** Output format. Default: jpeg */
	format?: "jpeg" | "png" | "webp";
	/** Quality levels to try (descending). Default: [80, 70, 60, 50, 40] */
	qualityLevels?: number[];
	/** Dimension step-down sequence. Default: [2048, 1024, 800] */
	dimensionSteps?: number[];
};

const DEFAULT_OPTIONS: Required<ImageOptimizeOptions> = {
	maxDimension: 2048,
	maxSizeBytes: 5 * 1024 * 1024, // 5MB
	format: "jpeg",
	qualityLevels: [80, 70, 60, 50, 40],
	dimensionSteps: [2048, 1024, 800],
};

/**
 * Result of image optimization.
 */
export type OptimizedImage = {
	buffer: Buffer;
	mimeType: string;
	width: number;
	height: number;
	originalWidth: number;
	originalHeight: number;
	quality: number;
	sizeBytes: number;
	originalSizeBytes: number;
	wasOptimized: boolean;
};

/**
 * Optimize an image buffer to reduce size while maintaining quality.
 *
 * Uses adaptive sizing and quality reduction:
 * 1. Start with largest dimension step that fits maxDimension
 * 2. Try each quality level until size is under maxSizeBytes
 * 3. If still too large, reduce dimension and repeat
 *
 * @param input - Image buffer or file path
 * @param options - Optimization options
 * @returns Optimized image data
 */
export async function optimizeImage(
	input: Buffer | string,
	options: ImageOptimizeOptions = {},
): Promise<OptimizedImage> {
	const opts = { ...DEFAULT_OPTIONS, ...options };

	// Load input
	const inputBuffer = typeof input === "string" ? await fs.promises.readFile(input) : input;
	const originalSize = inputBuffer.length;

	// Get original dimensions
	const metadata = await sharp(inputBuffer).metadata();
	const originalWidth = metadata.width ?? 0;
	const originalHeight = metadata.height ?? 0;

	if (!originalWidth || !originalHeight) {
		throw new Error("Could not determine image dimensions");
	}

	// If image is already small enough and within dimension limits, return as-is
	const maxOriginalDim = Math.max(originalWidth, originalHeight);
	if (originalSize <= opts.maxSizeBytes && maxOriginalDim <= opts.maxDimension) {
		logger.debug(
			{ originalSize, width: originalWidth, height: originalHeight },
			"image already within limits, skipping optimization",
		);

		return {
			buffer: inputBuffer,
			mimeType: `image/${metadata.format ?? "jpeg"}`,
			width: originalWidth,
			height: originalHeight,
			originalWidth,
			originalHeight,
			quality: 100,
			sizeBytes: originalSize,
			originalSizeBytes: originalSize,
			wasOptimized: false,
		};
	}

	// Try each dimension step
	for (const maxDim of opts.dimensionSteps) {
		if (maxDim > opts.maxDimension) continue;

		// Calculate resize dimensions maintaining aspect ratio
		let targetWidth = originalWidth;
		let targetHeight = originalHeight;

		if (maxOriginalDim > maxDim) {
			const scale = maxDim / maxOriginalDim;
			targetWidth = Math.round(originalWidth * scale);
			targetHeight = Math.round(originalHeight * scale);
		}

		// Try each quality level
		for (const quality of opts.qualityLevels) {
			const result = await compressImage(
				inputBuffer,
				targetWidth,
				targetHeight,
				quality,
				opts.format,
			);

			if (result.length <= opts.maxSizeBytes) {
				logger.debug(
					{
						originalSize,
						optimizedSize: result.length,
						originalDims: `${originalWidth}x${originalHeight}`,
						newDims: `${targetWidth}x${targetHeight}`,
						quality,
					},
					"image optimized successfully",
				);

				return {
					buffer: result,
					mimeType: `image/${opts.format}`,
					width: targetWidth,
					height: targetHeight,
					originalWidth,
					originalHeight,
					quality,
					sizeBytes: result.length,
					originalSizeBytes: originalSize,
					wasOptimized: true,
				};
			}
		}
	}

	// If we get here, use the smallest dimensions and lowest quality
	const minDim = opts.dimensionSteps[opts.dimensionSteps.length - 1] ?? 800;
	const minQuality = opts.qualityLevels[opts.qualityLevels.length - 1] ?? 40;

	const scale = Math.min(minDim / maxOriginalDim, 1);
	const targetWidth = Math.round(originalWidth * scale);
	const targetHeight = Math.round(originalHeight * scale);

	const result = await compressImage(
		inputBuffer,
		targetWidth,
		targetHeight,
		minQuality,
		opts.format,
	);

	logger.warn(
		{
			originalSize,
			optimizedSize: result.length,
			targetSize: opts.maxSizeBytes,
			quality: minQuality,
		},
		"image still exceeds target size after max optimization",
	);

	return {
		buffer: result,
		mimeType: `image/${opts.format}`,
		width: targetWidth,
		height: targetHeight,
		originalWidth,
		originalHeight,
		quality: minQuality,
		sizeBytes: result.length,
		originalSizeBytes: originalSize,
		wasOptimized: true,
	};
}

/**
 * Compress an image to a specific size and quality.
 */
async function compressImage(
	input: Buffer,
	width: number,
	height: number,
	quality: number,
	format: "jpeg" | "png" | "webp",
): Promise<Buffer> {
	let pipeline = sharp(input).resize(width, height, {
		fit: "inside",
		withoutEnlargement: true,
	});

	switch (format) {
		case "jpeg":
			pipeline = pipeline.jpeg({ quality, mozjpeg: true });
			break;
		case "png":
			pipeline = pipeline.png({ quality, compressionLevel: 9 });
			break;
		case "webp":
			pipeline = pipeline.webp({ quality });
			break;
	}

	return pipeline.toBuffer();
}

/**
 * Optimize an image and save to a file.
 *
 * @param input - Input image buffer or path
 * @param outputDir - Directory to save optimized image
 * @param options - Optimization options
 * @returns Path to the optimized image
 */
export async function optimizeAndSaveImage(
	input: Buffer | string,
	outputDir: string,
	options: ImageOptimizeOptions = {},
): Promise<{ path: string; result: OptimizedImage }> {
	const result = await optimizeImage(input, options);

	await fs.promises.mkdir(outputDir, { recursive: true, mode: 0o700 });

	const ext = options.format === "png" ? ".png" : options.format === "webp" ? ".webp" : ".jpg";
	const hash = crypto.createHash("sha256").update(result.buffer).digest("hex").slice(0, 16);
	const filename = `${Date.now()}-${hash}${ext}`;
	const filepath = path.join(outputDir, filename);

	await fs.promises.writeFile(filepath, result.buffer, { mode: 0o600 });

	return { path: filepath, result };
}

/**
 * Get image dimensions without loading the full image.
 */
export async function getImageDimensions(
	input: Buffer | string,
): Promise<{ width: number; height: number; format: string }> {
	const metadata =
		typeof input === "string" ? await sharp(input).metadata() : await sharp(input).metadata();

	return {
		width: metadata.width ?? 0,
		height: metadata.height ?? 0,
		format: metadata.format ?? "unknown",
	};
}
