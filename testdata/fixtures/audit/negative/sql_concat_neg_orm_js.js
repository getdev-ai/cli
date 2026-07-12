async function getUser(prisma, userId) {
  return prisma.user.findUnique({ where: { id: userId } });
}
