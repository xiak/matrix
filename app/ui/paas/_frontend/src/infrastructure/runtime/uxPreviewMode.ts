export const uxPreviewEnabled =
  process.env.NODE_ENV === "development" ||
  process.env.NEXT_PUBLIC_MATRIX_UX_PREVIEW === "1";
